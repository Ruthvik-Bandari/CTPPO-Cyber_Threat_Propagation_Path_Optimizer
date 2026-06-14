import { useEffect, useRef, useState, type ReactNode } from 'react'
import { motion, AnimatePresence } from 'motion/react'
import { ChevronLeft, ChevronRight, X, type LucideIcon } from 'lucide-react'
import { cn } from '@/lib/utils'

export interface CarouselCard {
  category: string
  title: string
  description: string
  stat?: string
  Icon: LucideIcon
  details: ReactNode
}

/*
 * Apple-style cards carousel: a horizontal, snap-scrolling track of cards that expand into a
 * shared-layout modal on click (motion layoutId morph). Arrow controls + Escape/backdrop close.
 */
export function AppleCarousel({ cards }: { cards: CarouselCard[] }) {
  const trackRef = useRef<HTMLDivElement>(null)
  const [active, setActive] = useState<number | null>(null)
  const closeRef = useRef<HTMLButtonElement>(null)

  useEffect(() => {
    if (active === null) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setActive(null)
    }
    window.addEventListener('keydown', onKey)
    closeRef.current?.focus()
    return () => window.removeEventListener('keydown', onKey)
  }, [active])

  const nudge = (dir: -1 | 1) => trackRef.current?.scrollBy({ left: dir * 360, behavior: 'smooth' })

  return (
    <div className="relative">
      <div
        ref={trackRef}
        className="no-scrollbar flex snap-x snap-mandatory gap-5 overflow-x-auto pb-4"
      >
        {cards.map((card, i) => (
          <motion.button
            layoutId={`card-${i}`}
            key={card.title}
            onClick={() => setActive(i)}
            whileHover={{ y: -6 }}
            className="group relative flex h-[26rem] w-[18rem] shrink-0 snap-start flex-col justify-between overflow-hidden rounded-3xl border border-line bg-surface/60 p-6 text-left backdrop-blur transition-colors hover:border-cyber/50 sm:w-[21rem]"
          >
            <div className="flex flex-col gap-4">
              <div className="flex w-fit rounded-2xl bg-cyber/10 p-3 text-cyber">
                <card.Icon className="h-6 w-6" />
              </div>
              <span className="text-xs font-medium uppercase tracking-widest text-cyber/80">
                {card.category}
              </span>
            </div>
            <div className="flex flex-col gap-2">
              <h3 className="text-2xl font-semibold leading-tight text-fg">{card.title}</h3>
              <p className="text-sm text-muted">{card.description}</p>
              {card.stat && (
                <span className="mt-2 font-mono text-sm text-cyber-bright">{card.stat}</span>
              )}
            </div>
            <div className="pointer-events-none absolute -right-16 -top-16 h-40 w-40 rounded-full bg-cyber/10 blur-2xl transition-opacity group-hover:opacity-100" />
          </motion.button>
        ))}
      </div>

      <div className="mt-2 flex items-center justify-end gap-2">
        <button
          onClick={() => nudge(-1)}
          aria-label="Scroll left"
          className="flex h-10 w-10 items-center justify-center rounded-full border border-line text-muted transition-colors hover:border-cyber/60 hover:text-cyber"
        >
          <ChevronLeft className="h-5 w-5" />
        </button>
        <button
          onClick={() => nudge(1)}
          aria-label="Scroll right"
          className="flex h-10 w-10 items-center justify-center rounded-full border border-line text-muted transition-colors hover:border-cyber/60 hover:text-cyber"
        >
          <ChevronRight className="h-5 w-5" />
        </button>
      </div>

      <AnimatePresence>
        {active !== null && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6">
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setActive(null)}
              className="absolute inset-0 bg-base/80 backdrop-blur-sm"
            />
            <motion.div
              layoutId={`card-${active}`}
              role="dialog"
              aria-modal="true"
              aria-label={cards[active].title}
              className={cn(
                'glass relative flex max-h-[85vh] w-full max-w-2xl flex-col gap-5 overflow-y-auto rounded-3xl p-8',
              )}
            >
              <button
                ref={closeRef}
                onClick={() => setActive(null)}
                aria-label="Close"
                className="absolute right-5 top-5 flex h-9 w-9 items-center justify-center rounded-full border border-line text-muted transition-colors hover:border-cyber/60 hover:text-cyber"
              >
                <X className="h-4 w-4" />
              </button>
              <div className="flex w-fit rounded-2xl bg-cyber/10 p-3 text-cyber">
                {(() => {
                  const Icon = cards[active].Icon
                  return <Icon className="h-7 w-7" />
                })()}
              </div>
              <div className="flex flex-col gap-1">
                <span className="text-xs font-medium uppercase tracking-widest text-cyber/80">
                  {cards[active].category}
                </span>
                <h3 className="text-3xl font-semibold text-fg">{cards[active].title}</h3>
              </div>
              <div className="text-muted">{cards[active].details}</div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  )
}
