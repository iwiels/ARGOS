import { createOpencodeClient, createOpencodeServer } from "@argos/sdk"
import { pathToFileURL } from "bun"

const server = await createOpencodeServer()
const client = createOpencodeClient({ baseUrl: server.url })

const input = await Array.fromAsync(new Bun.Glob("packages/core/*.ts").scan())

await Promise.all(
  input.map(async (file) => {
    const session = await client.session.create()
    console.log("processing", file)
    await client.session.prompt({
      path: { id: session.data.id },
      body: {
        parts: [
          {
            type: "file",
            mime: "text/plain",
            url: pathToFileURL(file).href,
          },
          {
            type: "text",
            text: `Write tests for every public function in this file.`,
          },
        ],
      },
    })
    console.log("done", file)
  }),
)


