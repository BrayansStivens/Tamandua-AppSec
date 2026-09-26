import * as React from "react"
import { Menu as MenuPrimitive } from "@base-ui/react/menu"
import { cn } from "cn"

// Menú de acciones (Base UI): roles ARIA de menú, flechas, Home/End, Escape y devolución del foco
// al botón que lo abrió. Sirve para agrupar acciones secundarias en lugar de una fila de botones.
const Menu = MenuPrimitive.Root
const MenuTrigger = MenuPrimitive.Trigger

function MenuContent({ className, children, side = "bottom", align = "end", sideOffset = 4, ...props }:
  MenuPrimitive.Popup.Props & Pick<MenuPrimitive.Positioner.Props, "side" | "align" | "sideOffset">) {
  return (
    <MenuPrimitive.Portal>
      <MenuPrimitive.Positioner side={side} align={align} sideOffset={sideOffset} className="isolate z-50">
        <MenuPrimitive.Popup
          data-slot="menu-content"
          className={cn("max-h-(--available-height) min-w-52 origin-(--transform-origin) overflow-y-auto rounded-lg bg-popover p-1 text-popover-foreground shadow-md ring-1 ring-foreground/10 outline-none", className)}
          {...props}
        >
          {children}
        </MenuPrimitive.Popup>
      </MenuPrimitive.Positioner>
    </MenuPrimitive.Portal>
  )
}

function MenuGroup({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <MenuPrimitive.Group className="py-0.5">
      <MenuPrimitive.GroupLabel className="px-2 pt-1.5 pb-1 text-xs font-medium text-app-muted">{label}</MenuPrimitive.GroupLabel>
      {children}
    </MenuPrimitive.Group>
  )
}

function MenuItem({ className, ...props }: MenuPrimitive.Item.Props) {
  return (
    <MenuPrimitive.Item
      data-slot="menu-item"
      className={cn("flex min-h-8 cursor-default items-center gap-2 rounded-md px-2 py-1.5 text-sm outline-none select-none data-highlighted:bg-app-soft data-highlighted:text-app-fg data-disabled:pointer-events-none data-disabled:opacity-50 [&_svg]:size-4 [&_svg]:shrink-0 [&_svg]:text-app-muted", className)}
      {...props}
    />
  )
}

function MenuSeparator() {
  return <MenuPrimitive.Separator className="my-1 h-px bg-app-line" />
}

export { Menu, MenuContent, MenuGroup, MenuItem, MenuSeparator, MenuTrigger }
