import { decode64 } from "@/utils/base64"

export function targetDirFromParams(params: { auditId?: string; dir?: string }) {
  if (params.auditId) return decode64(params.auditId) ?? params.auditId
  if (params.dir) return decode64(params.dir) ?? params.dir
  return ""
}
