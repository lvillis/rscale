import * as React from "react"

import { cn } from "@/lib/utils"

function Textarea({ className, ...props }: React.ComponentProps<"textarea">) {
  return (
    <textarea
      data-slot="textarea"
      className={cn(
        "flex field-sizing-content min-h-20 w-full rounded-[6px] border border-input bg-[var(--surface-soft)] px-3.5 py-3 text-[15px] leading-[1.6] tracking-[-0.165px] text-secondary-foreground transition-[border-color,box-shadow,background-color] outline-none placeholder:text-muted-foreground focus-visible:border-[rgba(113,112,255,0.42)] focus-visible:ring-[0_0_0_1px_rgba(113,112,255,0.22),0_4px_12px_rgba(0,0,0,0.18)] disabled:cursor-not-allowed disabled:bg-muted disabled:opacity-50 aria-invalid:border-destructive aria-invalid:ring-[0_0_0_1px_rgba(159,73,97,0.22)] md:text-[15px]",
        className
      )}
      {...props}
    />
  )
}

export { Textarea }
