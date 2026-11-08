import { Toast, showToast as showLegacyToast, type ToastOptions } from "@argos/ui/toast"

export function ToastRegion() {
  return <Toast.Region />
}

export function showToast(options: ToastOptions | string) {
  return showLegacyToast(options)
}
