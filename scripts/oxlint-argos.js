// oxlint-argos.js
// Plugin custom de Argos para oxlint (API compatible con ESLint v9).
//
// Regla: argos/icon-without-wrapper
// Detecta <Icon> "suelto": el componente Icon (o sus alias IconV2/Icon2)
// renderizado sin prop `size`, sin clase de dimensionamiento (w-*, h-*, size-*)
// y sin estar envuelto en un contenedor de layout conocido (IconButton, Button,
// o un wrapper con clase de tamaño). En el design system, un icono debe tener
// tamaño explícito o un contenedor que lo dimensione para mantener layout
// consistente y evitar iconos "flotantes".

const ICON_COMPONENT_NAMES = new Set(["Icon", "IconV2", "Icon2"])

// Componentes del design system que ya dimensionan su icono internamente.
const SIZING_WRAPPERS = new Set([
  "IconButton",
  "Button",
  "BasicTool",
  "ToolRun",
  "Select",
  "List",
  "MenuItem",
])

// Clases de Tailwind que otorgan dimensionamiento o layout al icono.
const SIZING_CLASS_RE =
  /(?:^|[\s"])(?:w|h|size|min-w|max-w|min-h|max-h)-[0-9.]+|(?:^|[\s"])(?:w|h|size)-(?:small|normal|large)|(?:^|[\s"])(?:size|w|h)-\[[^\]]+\]/

function openingElement(node) {
  return node.openingElement || node.openingFragment
}

function elementName(node) {
  const opening = openingElement(node)
  if (!opening) return undefined
  const name = opening.name
  if (!name) return undefined
  if (name.type === "JSXIdentifier") return name.name
  if (name.type === "JSXMemberExpression") {
    // e.g. <Menu.Icon>
    const parts = []
    let current = name
    while (current) {
      if (current.type === "JSXIdentifier") {
        parts.unshift(current.name)
        current = undefined
      } else if (current.type === "JSXMemberExpression") {
        if (current.property && current.property.name) parts.unshift(current.property.name)
        current = current.object
      } else {
        current = undefined
      }
    }
    return parts.join(".")
  }
  return undefined
}

function attributesOf(node) {
  const opening = openingElement(node)
  return opening?.attributes ?? []
}

function attributeValue(attrs, name) {
  for (const attr of attrs) {
    if (attr.type !== "JSXAttribute") continue
    const attrName = attr.name && attr.name.name
    if (attrName !== name) continue
    const value = attr.value
    if (!value) return { present: true }
    if (value.type === "Literal" || value.type === "StringLiteral") return { present: true, value: String(value.value) }
    if (value.type === "JSXExpressionContainer") {
      const expr = value.expression
      if (expr && (expr.type === "Literal" || expr.type === "StringLiteral")) {
        return { present: true, value: String(expr.value) }
      }
      // Template literals: concatenar los quasis para extraer las clases.
      // e.g. class={`size-4 text-gray-500 ${open() ? "rotate-90" : ""}`}
      if (expr && expr.type === "TemplateLiteral") {
        const text = (expr.quasis ?? []).map((q) => q.value?.cooked ?? q.value?.raw ?? "").join(" ")
        return { present: true, value: text }
      }
      return { present: true, dynamic: true }
    }
    return { present: true }
  }
  return { present: false }
}

function classNameOf(node) {
  const attrs = attributesOf(node)
  const cls = attributeValue(attrs, "class")
  const classList = attributeValue(attrs, "classList")
  return [cls.value, classList.value].filter(Boolean).join(" ")
}

// ¿El nodo es el valor de la prop `icon` de un wrapper conocido (IconButton,
// Button) o de un componente con `as={IconButton}`? En ese caso el wrapper
// dimensiona el icono internamente.
function isIconPropOfKnownWrapper(node) {
  let parent = node.parent
  while (parent) {
    if (parent.type === "JSXExpressionContainer" || parent.type === "JSXAttribute") {
      parent = parent.parent
      continue
    }
    if (parent.type === "JSXElement") {
      const name = elementName(parent)
      if (name && (SIZING_WRAPPERS.has(name) || name.endsWith(".Trigger"))) {
        // Verificar que el icono sea el valor de la prop `icon` de ese elemento.
        for (const attr of attributesOf(parent)) {
          if (attr.type !== "JSXAttribute") continue
          const attrName = attr.name && attr.name.name
          if (attrName === "icon" && attr.value) return true
          if (attrName === "as") {
            const v = attributeValue(attributesOf(parent), "as")
            if (v.value && SIZING_WRAPPERS.has(v.value)) return true
          }
        }
      }
      return false
    }
    parent = parent.parent
  }
  return false
}

// ¿El nodo está dentro de un slot CSS del design system (data-slot)? Solo en
// la librería (packages/ui) los data-slot vienen con CSS que dimensiona el
// icono ([data-slot="icon-svg"]). En la app, un data-slot propio NO garantiza
// dimensionamiento, así que ahí la regla sigue reportando.
function isInsideCssSlot(node, filename) {
  const inUiLib =
    typeof filename === "string" && /packages[\\/]ui[\\/]/.test(filename.replace(/\\/g, "/"))
  if (!inUiLib) return false
  let parent = node.parent
  let depth = 0
  while (parent && depth < 8) {
    if (parent.type === "JSXElement") {
      for (const attr of attributesOf(parent)) {
        if (attr.type === "JSXAttribute" && attr.name && attr.name.name === "data-slot") return true
      }
    }
    parent = parent.parent
    depth += 1
  }
  return false
}

function hasSizingClass(className) {
  return SIZING_CLASS_RE.test(className)
}

function isInsideSizingWrapper(node, wrappers) {
  let parent = node.parent
  let depth = 0
  while (parent && depth < 8) {
    if (parent.type === "JSXElement" || parent.type === "JSXFragment") {
      const name = elementName(parent)
      if (name && wrappers.has(name)) return true
      const className = classNameOf(parent)
      if (hasSizingClass(className)) return true
    }
    parent = parent.parent
    depth += 1
  }
  return false
}

const iconWithoutWrapper = {
  meta: {
    type: "suggestion",
    docs: {
      description: "Detecta <Icon> suelto sin wrapper ni dimensionamiento explícito.",
      category: "Design System",
    },
    schema: [
      {
        type: "object",
        properties: {
          iconComponents: { type: "array", items: { type: "string" } },
          sizingWrappers: { type: "array", items: { type: "string" } },
        },
        additionalProperties: false,
      },
    ],
  },
  create(context) {
    const options = context.options?.[0] ?? {}
    const iconNames = new Set(options.iconComponents ?? [...ICON_COMPONENT_NAMES])
    const wrappers = new Set(options.sizingWrappers ?? [...SIZING_WRAPPERS])

    return {
      JSXElement(node) {
        const name = elementName(node)
        if (!name || !iconNames.has(name)) return

        const attrs = attributesOf(node)

        // 1. Prop `size` explícita → dimensionado por el componente.
        const size = attributeValue(attrs, "size")
        if (size.present && (size.dynamic || size.value)) return

        // 2. Clase de dimensionamiento en el propio <Icon> → ok.
        const className = classNameOf(node)
        if (hasSizingClass(className)) return

        // 3. Envuelto en un componente que dimensiona (IconButton, Button…) o en
        //    un contenedor con clase de tamaño → ok.
        if (isInsideSizingWrapper(node, wrappers)) return

        // 4. Icono pasado como prop `icon={...}` de un wrapper (IconButton,
        //    Menu.Trigger as={IconButton}, etc.) → el wrapper lo dimensiona.
        if (isIconPropOfKnownWrapper(node)) return

        // 5. Icono dentro de un slot CSS del design system (data-slot) en la
        //    librería → el CSS del slot lo dimensiona.
        if (isInsideCssSlot(node, context.filename)) return

        context.report({
          node,
          message: `<${name}> sin wrapper ni tamaño explícito: agrégale prop size= o clase w-*/h-*/size-*, o envuélvelo en <IconButton>/<Button>.`,
        })
      },
    }
  },
}

export default {
  meta: {
    name: "argos",
    version: "0.1.0",
  },
  rules: {
    "icon-without-wrapper": iconWithoutWrapper,
  },
}
