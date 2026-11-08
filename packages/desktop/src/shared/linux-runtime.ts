export const LINUX_NODE_VERSION = "24.21.0"
export const LINUX_NODE_ARCHIVES = {
  amd64: {
    asset: `node-v${LINUX_NODE_VERSION}-linux-x64.tar.xz`,
    sha256: "fd8e59d5a511510f6a298afb548f18c7d2b1be404d8b4a27d94fbe49f56cb2d6",
  },
  arm64: {
    asset: `node-v${LINUX_NODE_VERSION}-linux-arm64.tar.xz`,
    sha256: "6ad1325edbdb5649c379b75a237147a666c95d4f9ae8d340fef2d1575d289ad2",
  },
} as const
