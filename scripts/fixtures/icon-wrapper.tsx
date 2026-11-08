// Fixture para probar la regla argos/icon-without-wrapper
import { Icon } from "@argos/ui/icon"
import { IconButton } from "@argos/ui/icon-button"
import { Button } from "@argos/ui/button"

// ── Casos VÁLIDOS (no deben reportarse) ──────────────────────────────────────

export function ValidCases() {
  return (
    <>
      {/* prop size explícita */}
      <Icon name="search" size="small" />
      <Icon name="menu" size="large" />

      {/* clase de dimensionamiento */}
      <Icon name="server" class="w-6 h-6 text-accent" />
      <Icon name="shield" class="size-3.5 shrink-0" />
      <Icon name="magnifying-glass" class="absolute left-2.5 top-1/2 size-4" />

      {/* envuelto en IconButton (dimensiona internamente) */}
      <IconButton icon="plus" variant="ghost" />
      <IconButton icon={<Icon name="plus" />} variant="ghost" />

      {/* envuelto en Button */}
      <Button icon="plus">Nueva Auditoría</Button>

      {/* envuelto en un contenedor con clase de tamaño */}
      <div class="size-8 flex items-center justify-center">
        <Icon name="help" />
      </div>

      {/* clase de dimensionamiento en template literal */}
      <Icon name="chevron-right" class={`size-4 text-gray-500 ${open() ? "rotate-90" : ""}`} />

      {/* como prop icon= de un wrapper (IconButton / Menu.Trigger as={IconButton}) */}
      <IconButton icon={<Icon name="plus" />} variant="ghost" />
      <Menu.Trigger as={IconButton} icon={<IconV2 name="outline-dots" />} />

      {/* dentro de un slot CSS con clase de tamaño en el ancestro */}
      <div data-slot="list-search-container" class="size-6">
        <Icon name="magnifying-glass" />
      </div>
    </>
  )
}

// ── Casos INVÁLIDOS (deben reportarse) ───────────────────────────────────────

export function InvalidCases() {
  return (
    <>
      {/* suelto, sin size ni clase ni wrapper */}
      <Icon name="console" />
      <Icon name="edit" />

      {/* suelto dentro de un div sin dimensionamiento */}
      <div class="flex items-center gap-2">
        <Icon name="branch" />
      </div>

      {/* alias IconV2 también debe detectarse */}
      <IconV2 name="server" />

      {/* suelto dentro de un slot con data-slot */}
      <div data-slot="my-custom-app-slot">
        <Icon name="warning" />
      </div>
    </>
  )
}
