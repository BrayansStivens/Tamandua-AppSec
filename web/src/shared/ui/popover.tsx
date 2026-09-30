import { Popover as PopoverPrimitive } from "@base-ui/react/popover"
import { cn } from "cn"

// Non-modal panel anchored to its trigger (Base UI): Escape and a click outside close it, and the focus returns to
// the trigger. For details that must not take over the view.
const Popover = PopoverPrimitive.Root
const PopoverTrigger = PopoverPrimitive.Trigger
const PopoverTitle = PopoverPrimitive.Title

function PopoverContent({ className, children, side = "bottom", align = "end", sideOffset = 6, ...props }:
  PopoverPrimitive.Popup.Props & Pick<PopoverPrimitive.Positioner.Props, "side" | "align" | "sideOffset">) {
  return (
    <PopoverPrimitive.Portal>
      <PopoverPrimitive.Positioner side={side} align={align} sideOffset={sideOffset} className="isolate z-50">
        <PopoverPrimitive.Popup
          data-slot="popover-content"
          className={cn("max-h-(--available-height) w-96 max-w-[calc(100vw-2rem)] overflow-y-auto rounded-xl border border-app-line bg-panel p-4 text-app-fg shadow-xl outline-none", className)}
          {...props}
        >
          {children}
        </PopoverPrimitive.Popup>
      </PopoverPrimitive.Positioner>
    </PopoverPrimitive.Portal>
  )
}

export { Popover, PopoverContent, PopoverTitle, PopoverTrigger }
