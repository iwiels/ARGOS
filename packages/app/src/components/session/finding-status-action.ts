export async function persistFindingStatusChange(
  save: () => Promise<boolean>,
  applyLocal: () => void,
): Promise<boolean> {
  try {
    if (!(await save())) return false
    applyLocal()
    return true
  } catch {
    return false
  }
}
