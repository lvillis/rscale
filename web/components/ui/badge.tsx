import { mergeProps } from "@base-ui/react/merge-props"
import { useRender } from "@base-ui/react/use-render"
import { cva, type VariantProps } from "class-variance-authority"

import { cn } from "@/lib/utils"

const badgeVariants = cva(
  "group/badge inline-flex h-6 w-fit shrink-0 items-center justify-center gap-1 overflow-hidden rounded-full border px-2.5 py-0.5 text-[12px] leading-none font-[510] tracking-[-0.13px] whitespace-nowrap transition-colors focus-visible:border-ring focus-visible:ring-[0_0_0_1px_rgba(113,112,255,0.22)] has-data-[icon=inline-end]:pr-2 has-data-[icon=inline-start]:pl-2 aria-invalid:border-destructive [&>svg]:pointer-events-none [&>svg]:size-3!",
  {
    variants: {
      variant: {
        default: "border-transparent bg-primary text-primary-foreground [a]:hover:bg-[#7170ff]",
        secondary:
          "border-border/70 bg-secondary text-foreground [a]:hover:bg-[var(--surface-hover)]",
        destructive:
          "border-destructive/25 bg-destructive/10 text-destructive-foreground [a]:hover:bg-destructive/15",
        outline:
          "border-border bg-transparent text-secondary-foreground [a]:hover:bg-[var(--surface-soft)] [a]:hover:text-foreground",
        ghost:
          "border-transparent bg-[var(--surface-soft)] text-secondary-foreground hover:bg-[var(--surface-hover)] hover:text-foreground",
        link: "border-transparent bg-transparent px-0 text-primary hover:text-accent hover:underline underline-offset-4",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
)

function Badge({
  className,
  variant = "default",
  render,
  ...props
}: useRender.ComponentProps<"span"> & VariantProps<typeof badgeVariants>) {
  return useRender({
    defaultTagName: "span",
    props: mergeProps<"span">(
      {
        className: cn(badgeVariants({ variant }), className),
      },
      props
    ),
    render,
    state: {
      slot: "badge",
      variant,
    },
  })
}

export { Badge, badgeVariants }
