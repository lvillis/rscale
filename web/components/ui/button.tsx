import { Button as ButtonPrimitive } from "@base-ui/react/button"
import { cva, type VariantProps } from "class-variance-authority"

import { cn } from "@/lib/utils"

const buttonVariants = cva(
  "group/button inline-flex shrink-0 items-center justify-center rounded-[6px] border bg-clip-padding text-[13px] leading-none font-[510] tracking-[-0.13px] whitespace-nowrap text-foreground transition-[background-color,border-color,color,box-shadow] outline-none select-none focus-visible:border-[rgba(113,112,255,0.42)] focus-visible:ring-[0_0_0_1px_rgba(113,112,255,0.26),0_4px_12px_rgba(0,0,0,0.18)] active:not-aria-[haspopup]:translate-y-px disabled:pointer-events-none disabled:opacity-45 aria-invalid:border-destructive aria-invalid:ring-[0_0_0_1px_rgba(159,73,97,0.28)] [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4",
  {
    variants: {
      variant: {
        default:
          "border-transparent bg-primary text-primary-foreground shadow-[inset_0_1px_0_rgba(255,255,255,0.12)] hover:brightness-[1.06]",
        outline:
          "border-border bg-[var(--surface-elevated)] text-foreground hover:bg-[var(--surface-hover)] aria-expanded:bg-[var(--surface-hover)]",
        secondary:
          "border-border/70 bg-secondary text-secondary-foreground hover:bg-[var(--surface-hover)] hover:text-foreground aria-expanded:bg-[var(--surface-hover)]",
        ghost:
          "border-transparent bg-transparent text-secondary-foreground hover:bg-[var(--surface-soft)] hover:text-foreground aria-expanded:bg-[var(--surface-soft)] aria-expanded:text-foreground",
        destructive:
          "border-destructive/25 bg-destructive/10 text-destructive-foreground hover:bg-destructive/15 focus-visible:border-[rgba(159,73,97,0.42)] focus-visible:ring-[0_0_0_1px_rgba(159,73,97,0.26)]",
        link: "border-transparent bg-transparent px-0 text-primary hover:text-accent hover:underline underline-offset-4",
      },
      size: {
        default:
          "h-9 gap-1.5 px-4 has-data-[icon=inline-end]:pr-3 has-data-[icon=inline-start]:pl-3",
        xs: "h-6 gap-1 rounded-[4px] px-2 text-[11px] in-data-[slot=button-group]:rounded-[4px] has-data-[icon=inline-end]:pr-1.5 has-data-[icon=inline-start]:pl-1.5 [&_svg:not([class*='size-'])]:size-3",
        sm: "h-8 gap-1 rounded-[6px] px-3 text-[12px] in-data-[slot=button-group]:rounded-[6px] has-data-[icon=inline-end]:pr-2 has-data-[icon=inline-start]:pl-2 [&_svg:not([class*='size-'])]:size-3.5",
        lg: "h-10 gap-2 px-4 text-[14px] has-data-[icon=inline-end]:pr-3 has-data-[icon=inline-start]:pl-3",
        icon: "size-9 rounded-full",
        "icon-xs":
          "size-6 rounded-full in-data-[slot=button-group]:rounded-full [&_svg:not([class*='size-'])]:size-3",
        "icon-sm":
          "size-8 rounded-full in-data-[slot=button-group]:rounded-full",
        "icon-lg": "size-10 rounded-full",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  }
)

function Button({
  className,
  variant = "default",
  size = "default",
  ...props
}: ButtonPrimitive.Props & VariantProps<typeof buttonVariants>) {
  return (
    <ButtonPrimitive
      data-slot="button"
      className={cn(buttonVariants({ variant, size, className }))}
      {...props}
    />
  )
}

export { Button, buttonVariants }
