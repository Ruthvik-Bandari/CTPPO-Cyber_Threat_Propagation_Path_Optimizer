import { type ClassValue, clsx } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function formatDate(date: string | Date): string {
  return new Date(date).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric'
  })
}

export function formatTime(ms: number): string {
  if (ms < 1000) return `${ms.toFixed(0)}ms`
  return `${(ms / 1000).toFixed(2)}s`
}

export function getSeverityColor(severity: string): string {
  const colors: Record<string, string> = {
    CRITICAL: '#dc2626',
    HIGH: '#ea580c',
    MEDIUM: '#ca8a04',
    LOW: '#16a34a',
  }
  return colors[severity] || '#6b7280'
}

export function getSeverityGradient(severity: string): string {
  const gradients: Record<string, string> = {
    CRITICAL: 'from-red-600 to-red-500',
    HIGH: 'from-orange-600 to-orange-500',
    MEDIUM: 'from-yellow-600 to-yellow-500',
    LOW: 'from-green-600 to-green-500',
  }
  return gradients[severity] || 'from-gray-600 to-gray-500'
}
