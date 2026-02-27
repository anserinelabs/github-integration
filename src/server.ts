import crypto from 'crypto';

import express from 'express';

const PORT = 3334;

const SLASHWORK_AUTH_TOKEN = process.env.SLASHWORK_AUTH_TOKEN;
const SLASHWORK_GROUP_ID = process.env.SLASHWORK_GROUP_ID;
const GITHUB_WEBHOOK_SECRET = process.env.GITHUB_WEBHOOK_SECRET;
const SLASHWORK_GRAPHQL_URL = 'https://anserine.slashwork.com/api/graphql';

if (!SLASHWORK_AUTH_TOKEN || !SLASHWORK_GROUP_ID || !GITHUB_WEBHOOK_SECRET) {
  throw new Error('Missing required environment variables');
}

type GitHubCommit = {
  id: string;
  message: string;
  author: { name: string; email: string; username?: string };
  committer: { name: string; email: string; username?: string };
  url: string;
};

type GitHubPushEvent = {
  ref: string;
  repository: { full_name: string };
  commits: GitHubCommit[];
};

type GraphQLResponse = {
  data?: {
    createPost: {
      node: {
        id: string;
      };
    };
  };
  errors?: { message: string }[];
};

async function postToSlashwork(markdown: string): Promise<void> {
  const mutation = `
    mutation CreatePost($groupId: ID!, $input: CreatePostMutationInput!) {
      createPost(groupId: $groupId, input: $input) {
        node {
          id
        }
      }
    }
  `;

  const variables = {
    groupId: SLASHWORK_GROUP_ID,
    input: {
      markdown,
    },
  };

  const response = await fetch(SLASHWORK_GRAPHQL_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${SLASHWORK_AUTH_TOKEN}`,
    },
    body: JSON.stringify({
      query: mutation,
      variables,
    }),
  });

  if (!response.ok) {
    const errorText = await response.text();
    console.error('Failed to post to Slashwork:', errorText);
    throw new Error(`Slashwork API error: ${response.status}`);
  }

  const result = (await response.json()) as GraphQLResponse;
  if (result.errors) {
    console.error('GraphQL errors:', result.errors);
    throw new Error('GraphQL mutation failed');
  }

  if (!result.data) {
    throw new Error('No data in GraphQL response');
  }

  console.log(
    'Successfully posted to Slashwork:',
    result.data.createPost.node.id,
  );
}

function formatCommitPost(commit: GitHubCommit, repoFullName: string): string {
  const [title, ...rest] = commit.message.split('\n');
  const description = rest.join('\n').trim();
  const shortHash = commit.id.slice(0, 7);
  const committer = commit.committer.name || commit.author.name;

  const markdown = `__${title}__

${description ? 'Description: \n' + description + '\n\n' : ''}

**[${repoFullName}]**
[\`${shortHash}\`](${commit.url})

Committed by ${committer}`;

  return markdown;
}

const app = express();

// Use raw body so we can verify the HMAC signature before parsing JSON
app.use(express.raw({ type: 'application/json' }));

function verifySignatureMiddleware(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
): void {
  const signature = req.headers['x-hub-signature-256'];
  if (!signature || typeof signature !== 'string') {
    res.sendStatus(401);
    return;
  }

  const hmac = crypto.createHmac('sha256', GITHUB_WEBHOOK_SECRET!);
  hmac.update(req.body as Buffer);
  const expected = `sha256=${hmac.digest('hex')}`;

  try {
    if (
      signature.length === expected.length &&
      crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))
    ) {
      next();
    } else {
      res.sendStatus(401);
    }
  } catch {
    res.sendStatus(401);
  }
}

app.post('/webhook/github', verifySignatureMiddleware, (req, res) => {
  res.sendStatus(200);

  const event = req.headers['x-github-event'];
  if (event !== 'push') {
    return;
  }

  let payload: GitHubPushEvent;
  try {
    payload = JSON.parse((req.body as Buffer).toString()) as GitHubPushEvent;
  } catch {
    console.error('Failed to parse webhook payload');
    return;
  }

  // Skip tag pushes — only handle branch commits
  if (!payload.ref.startsWith('refs/heads/')) {
    return;
  }

  const { commits, repository } = payload;
  if (!commits || commits.length === 0) {
    return;
  }

  for (const commit of commits) {
    const markdown = formatCommitPost(commit, repository.full_name);
    postToSlashwork(markdown).catch((err: unknown) => {
      console.error('Failed to post commit to Slashwork:', err);
    });
  }
});

app.listen(PORT, () => {
  console.log(`Github webhook server listening on port ${PORT}`);
});
