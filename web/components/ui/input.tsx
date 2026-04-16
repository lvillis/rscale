import * as React from "react"
import { Input as InputPrimitive } from "@base-ui/react/input"

import { cn } from "@/lib/utils"

function Input({ className, type, ...props }: React.ComponentProps<"input">) {
  return (
    <InputPrimitive
      type={type}
      data-slot="input"
      className={cn(
        "h-10 w-full min-w-0 rounded-[6px] border border-input bg-[var(--surface-soft)] px-3.5 py-2 text-[15px] leading-[1.6] tracking-[-0.165px] text-foreground transition-[border-color,box-shadow,background-color] outline-none file:inline-flex file:h-6 file:border-0 file:bg-transparent file:text-sm file:font-[510] file:text-foreground placeholder:text-muted-foreground focus-visible:border-[rgba(113,112,255,0.42)] focus-visible:ring-[0_0_0_1px_rgba(113,112,255,0.22),0_4px_12px_rgba(0,0,0,0.18)] disabled:pointer-events-none disabled:cursor-not-allowed disabled:bg-muted disabled:opacity-50 aria-invalid:border-destructive aria-invalid:ring-[0_0_0_1px_rgba(159,73,97,0.22)] md:text-[15px]",
        className
      )}
      {...props}
    />
  )
}

export { Input }
