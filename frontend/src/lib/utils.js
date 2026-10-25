import { clsx } from 'clsx'
import { twMerge } from 'tailwind-merge'

/** Merges conditional classes, letting callers override component defaults. */
export function cn(...inputs) {
  return twMerge(clsx(inputs))
}
