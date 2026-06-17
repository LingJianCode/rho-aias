import type {
  RolesDirective,
  RippleDirective,
  HighlightDirective
} from '@/directives'

declare module 'vue' {
  export interface GlobalDirectives {
    vRoles: RolesDirective
    vRipple: RippleDirective
    vHighlight: HighlightDirective
  }
}
