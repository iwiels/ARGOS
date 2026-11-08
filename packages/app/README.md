# Argos App

SolidJS renderer used by Argos Desktop. It communicates with the Electron main process through the window.api bridge and uses the Argos server API for application data.

## Development

From the repository root:

~~~bash
pnpm install
pnpm dev:web
~~~

The standalone renderer development server uses http://localhost:4444 by default. For the full desktop application, use pnpm dev.

## Tests and build

~~~bash
pnpm --filter @argos/app test
pnpm --filter @argos/app build
~~~

Playwright end-to-end tests are maintained under packages/app/e2e/. Their server and browser prerequisites are defined by the Playwright configuration; this renderer is not a standalone static product deployment.