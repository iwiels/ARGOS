import { ErrorPage } from "@/pages/error"
import * as Sentry from "@sentry/solid"
import { ErrorBoundary, type ParentProps } from "solid-js"

/**
 * Boundary por subárbol de ruta: un panel o página que falle degrada a la
 * pantalla de error dentro del shell, en vez de desmontar toda la app
 * (el boundary raíz queda como último recurso).
 */
export function RouteErrorBoundary(props: ParentProps) {
  return (
    <ErrorBoundary
      fallback={(error) => {
        Sentry.captureException(error)
        return <ErrorPage error={error} />
      }}
    >
      {props.children}
    </ErrorBoundary>
  )
}
