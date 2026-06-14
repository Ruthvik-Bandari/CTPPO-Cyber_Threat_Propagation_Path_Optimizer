import { motion } from 'motion/react'
import type { ReactNode } from 'react'

interface ScrollRevealProps {
  children: ReactNode
  delay?: number
  y?: number
  className?: string
}

/* Fade + rise into view on scroll, once. Respects reduced-motion via the CSS guard. */
export function ScrollReveal({ children, delay = 0, y = 28, className }: ScrollRevealProps) {
  return (
    <motion.div
      className={className}
      initial={{ opacity: 0, y }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: '-80px' }}
      transition={{ duration: 0.6, delay, ease: [0.16, 1, 0.3, 1] }}
    >
      {children}
    </motion.div>
  )
}
