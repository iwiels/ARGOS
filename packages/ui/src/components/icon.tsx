import { type ComponentProps, splitProps } from "solid-js"
import { PIXEL_ICONS } from "./pixel-icons.data"

const icons = {
  edit: {
    viewBox: "0 0 16 16",
    body: `<path d="M13.5555 8.21534V13.5556H2.44434L2.44434 2.4445H7.78462M6.88878 9.11119C6.88878 9.11119 8.96327 9.0367 9.69678 8.3032L14.0301 3.96986C14.5824 3.4176 14.5824 2.52213 14.0301 1.96986C13.4778 1.4176 12.5824 1.4176 12.0301 1.96986L7.69678 6.3032C7.00513 6.99484 6.88878 9.11119 6.88878 9.11119Z" stroke="currentColor"/>`,
  },
  "folder-add-left": {
    viewBox: "0 0 16 16",
    body: `<path d="M7.5 13.3333H1.5V2H6.83333L8.83333 4H14.8333V6M10.1667 11.3333H15.5M12.8333 8.66667V14" stroke="currentColor" stroke-miterlimit="10" stroke-linecap="square"/>`,
  },
  "grid-plus": {
    viewBox: "0 0 16 16",
    body: `<path d="M13.9948 11.668H9.32812M11.6641 9.33203V13.9987M6.66667 9.33203V13.9987H2V9.33203H6.66667ZM6.66667 2V6.66667H2V2H6.66667ZM13.9948 2V6.66667H9.32812V2H13.9948Z" stroke="currentColor" stroke-miterlimit="10" stroke-linecap="square"/>`,
  },
  help: {
    viewBox: "0 0 16 16",
    body: `<path d="M6.33345 6.33349V5.00015H9.66679V7.00015L8.00015 8.00015V9.66679M8.27485 11.6819H7.71897M14.4446 8.00011C14.4446 11.5593 11.5593 14.4446 8.00011 14.4446C4.44094 14.4446 1.55566 11.5593 1.55566 8.00011C1.55566 4.44094 4.44094 1.55566 8.00011 1.55566C11.5593 1.55566 14.4446 4.44094 14.4446 8.00011Z" stroke="currentColor" stroke-linecap="square"/>`,
  },
  "sidebar-right": {
    viewBox: "0 0 20 20",
    body: `<path d="M2.91536 2.91406H2.36536V2.36406H2.91536V2.91406ZM2.91536 17.0807V17.6307H2.36536V17.0807H2.91536ZM17.082 17.0807H17.632V17.6307H17.082V17.0807ZM17.082 2.91406V2.36406H17.632V2.91406H17.082ZM6.9987 2.91406H6.4487V2.36406H6.9987V2.91406ZM6.9987 17.0807V17.6307H6.4487V17.0807H6.9987ZM2.91536 2.91406H3.46536V17.0807H2.91536H2.36536V2.91406H2.91536ZM2.91536 17.0807V16.5307H17.082V17.0807V17.6307H2.91536V17.0807ZM17.082 17.0807H16.532V2.91406H17.082H17.632V17.0807H17.082ZM17.082 2.91406V3.46406H2.91536V2.91406V2.36406H17.082V2.91406ZM6.9987 2.91406H7.5487V17.0807H6.9987H6.4487V2.91406H6.9987ZM17.082 17.0807L17.082 17.6307L6.9987 17.6307V17.0807V16.5307L17.082 16.5307L17.082 17.0807ZM6.9987 2.91406V2.36406H17.082V2.91406V3.46406H6.9987V2.91406Z" fill="currentColor"/>`,
  },
  status: {
    viewBox: "0 0 20 20",
    body: `<path d="M2 10V18H18V10M2 10V2H18V10M2 10H18M5 6H9M5 14H9" stroke="currentColor"/>`,
  },
  "status-active": {
    viewBox: "0 0 20 20",
    body: `<path d="M18 2H2V10H18V2Z" fill="currentColor" fill-opacity="0.1"/><path d="M2 18H18V10H2V18Z" fill="currentColor" fill-opacity="0.1"/><path d="M2 10V18H18V10M2 10V2H18V10M2 10H18M5 6H9M5 14H9" stroke="currentColor"/>`,
  },
  "magnifying-glass": {
    viewBox: "0 0 16 16",
    body: `<path d="M14 14L10.3454 10.3454M6.88889 11.7778C9.58889 11.7778 11.7778 9.58889 11.7778 6.88889C11.7778 4.18889 9.58889 2 6.88889 2C4.18889 2 2 4.18889 2 6.88889C2 9.58889 4.18889 11.7778 6.88889 11.7778Z" stroke="currentColor"/>`,
  },
  menu: {
    viewBox: "0 0 16 16",
    body: `<path d="M2 8H14M2 4.664H14M2 11.336H14" stroke="currentColor"/>`,
  },
  plus: {
    viewBox: "0 0 16 16",
    body: `<path d="M8 2.88867V13.1109" stroke="currentColor" stroke-linejoin="round"/><path d="M2.88867 8H13.1109" stroke="currentColor" stroke-linejoin="round"/>`,
  },
  "settings-gear": {
    viewBox: "0 0 16 16",
    body: `<path d="M7.99998 1.3335L14 4.66683V11.3335L7.99998 14.6668L2 11.3335V4.66683L7.99998 1.3335Z" stroke="currentColor"/><path d="M9.99998 8.00016C9.99998 9.10476 9.10458 10.0002 7.99998 10.0002C6.89538 10.0002 5.99998 9.10476 5.99998 8.00016C5.99998 6.89556 6.89538 6.00016 7.99998 6.00016C9.10458 6.00016 9.99998 6.89556 9.99998 8.00016Z" stroke="currentColor"/>`,
  },
  "chevron-down": {
    viewBox: "0 0 16 16",
    body: `<path d="M4.5 6.5L8 10L11.5 6.5" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/>`,
  },
  close: {
    viewBox: "0 0 20 20",
    body: `<path d="M14.4446 5.55566L5.55566 14.4446M5.55566 5.55566L14.4446 14.4446" stroke="currentColor" stroke-linejoin="round"/>`,
  },
  "xmark-small": {
    viewBox: "0 0 16 16",
    body: `<path d="M4.25 11.75L11.75 4.25M11.75 11.75L4.25 4.25" stroke="currentColor"/>`,
  },
  "outline-chevron-down": {
    viewBox: "0 0 16 16",
    body: `<path d="M4.5 6.5L8 10L11.5 6.5" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/>`,
  },
  "dot-grid": {
    viewBox: "0 0 16 16",
    body: `<circle cx="3" cy="3" r="1.25" fill="currentColor"/><circle cx="8" cy="3" r="1.25" fill="currentColor"/><circle cx="13" cy="3" r="1.25" fill="currentColor"/><circle cx="3" cy="8" r="1.25" fill="currentColor"/><circle cx="8" cy="8" r="1.25" fill="currentColor"/><circle cx="13" cy="8" r="1.25" fill="currentColor"/><circle cx="3" cy="13" r="1.25" fill="currentColor"/><circle cx="8" cy="13" r="1.25" fill="currentColor"/><circle cx="13" cy="13" r="1.25" fill="currentColor"/>`,
  },
  "plus-small": {
    viewBox: "0 0 16 16",
    body: `<path d="M8 4.5V11.5M4.5 8H11.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>`,
  },
  "check-small": {
    viewBox: "0 0 16 16",
    body: `<path d="M3.25 8.25L6.5 11.25L12.75 4.75" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>`,
  },
  stop: {
    viewBox: "0 0 16 16",
    body: `<rect x="3.5" y="3.5" width="9" height="9" rx="1.5" fill="currentColor"/>`,
  },
  home: {
    viewBox: "0 0 16 16",
    body: `<path d="M2.5 7L8 2.5L13.5 7V13.5H10V9.5H6V13.5H2.5V7Z" stroke="currentColor" fill="none" stroke-width="1.25"/>`,
  },
  console: {
    viewBox: "0 0 16 16",
    body: `<path d="M2.5 4L6.5 8L2.5 12M8.5 12H13.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>`,
  },
  search: {
    viewBox: "0 0 16 16",
    body: `<path d="M14 14L10.35 10.35M6.88 11.77C9.58 11.77 11.77 9.58 11.77 6.88C11.77 4.18 9.58 2 6.88 2C4.18 2 2 4.18 2 6.88C2 9.58 4.18 11.77 6.88 11.77Z" stroke="currentColor" stroke-width="1.5"/>`,
  },
  shield: {
    viewBox: "0 0 16 16",
    body: `<path d="M8 2L2.5 4.5V8.5C2.5 11.8 4.8 14.8 8 15.5C11.2 14.8 13.5 11.8 13.5 8.5V4.5L8 2Z" stroke="currentColor" fill="none" stroke-width="1.25"/>`,
  },
  checklist: {
    viewBox: "0 0 16 16",
    body: `<path d="M2.5 4.5H4.5M6.5 4.5H13.5M2.5 8H4.5M6.5 8H13.5M2.5 11.5H4.5M6.5 11.5H13.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>`,
  },
  server: {
    viewBox: "0 0 16 16",
    body: `<rect x="2.5" y="2.5" width="11" height="4.5" rx="1" stroke="currentColor" fill="none" stroke-width="1.25"/><rect x="2.5" y="9" width="11" height="4.5" rx="1" stroke="currentColor" fill="none" stroke-width="1.25"/><circle cx="5" cy="4.75" r="0.75" fill="currentColor"/><circle cx="5" cy="11.25" r="0.75" fill="currentColor"/>`,
  },
  "arrow-up": {
    viewBox: "0 0 16 16",
    body: `<path d="M8 13.5V2.5M8 2.5L3.5 7M8 2.5L12.5 7" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>`,
  },
  download: {
    viewBox: "0 0 16 16",
    body: `<path d="M8 2.5V13.5M8 13.5L3.5 9M8 13.5L12.5 9" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>`,
  },
  folder: {
    viewBox: "0 0 16 16",
    body: `<path d="M2 3.5H6.5L8 5H14V12.5H2V3.5Z" stroke="currentColor" fill="none" stroke-width="1.25"/>`,
  },
  brain: {
    viewBox: "0 0 16 16",
    body: `<path d="M6 3C4.34315 3 3 4.34315 3 6C3 6.70327 3.24218 7.34988 3.64931 7.86175C3.24218 8.37362 3 9.02023 3 9.7235C3 11.3803 4.34315 12.7235 6 12.7235C6.46749 12.7235 6.90684 12.617 7.3 12.4277V3.5723C6.90684 3.38299 6.46749 3 6 3ZM10 3C10.4675 3 10.9068 3.38299 11.3 3.5723V12.4277C10.9068 12.617 10.4675 12.7235 10 12.7235C8.34315 12.7235 7 11.3803 7 9.7235C7 9.02023 7.24218 8.37362 7.64931 7.86175C7.24218 7.34988 7 6.70327 7 6C7 4.34315 8.34315 3 10 3Z" stroke="currentColor" fill="none" stroke-width="1.2"/>`,
  },
  mcp: {
    viewBox: "0 0 16 16",
    body: `<rect x="5.25" y="5.25" width="5.5" height="5.5" rx="1" stroke="currentColor" fill="none" stroke-width="1.2"/><path d="M2.5 8H5M11 8H13.5M8 2.5V5M8 11V13.5" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/><circle cx="2.5" cy="8" r="0.8" fill="currentColor"/><circle cx="13.5" cy="8" r="0.8" fill="currentColor"/><circle cx="8" cy="2.5" r="0.8" fill="currentColor"/><circle cx="8" cy="13.5" r="0.8" fill="currentColor"/>`,
  },
  task: {
    viewBox: "0 0 16 16",
    body: `<circle cx="8" cy="4.5" r="2" stroke="currentColor" fill="none" stroke-width="1.2"/><circle cx="4.5" cy="11.5" r="1.75" stroke="currentColor" fill="none" stroke-width="1.2"/><circle cx="11.5" cy="11.5" r="1.75" stroke="currentColor" fill="none" stroke-width="1.2"/><path d="M6.9 6.2L5.3 9.8M9.1 6.2L10.7 9.8" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/>`,
  },
  globe: {
    viewBox: "0 0 16 16",
    body: `<circle cx="8" cy="8" r="5.75" stroke="currentColor" fill="none" stroke-width="1.15"/><path d="M2.25 8H13.75M8 2.25C9.5 4.2 10.2 6.1 10.2 8C10.2 9.9 9.5 11.8 8 13.75C6.5 11.8 5.8 9.9 5.8 8C5.8 6.1 6.5 4.2 8 2.25Z" stroke="currentColor" fill="none" stroke-width="1.1"/>`,
  },
  terminal: {
    viewBox: "0 0 16 16",
    body: `<rect x="2" y="3" width="12" height="10" rx="1.5" stroke="currentColor" fill="none" stroke-width="1.2"/><path d="M5 6L7.5 8L5 10M9 10H11" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/>`,
  },
  copy: {
    viewBox: "0 0 16 16",
    body: `<rect x="5" y="5" width="8" height="8" rx="1" stroke="currentColor" fill="none" stroke-width="1.2"/><path d="M3 11V3H11" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/>`,
  },
  paperclip: {
    viewBox: "0 0 16 16",
    body: `<path d="M10.5 4.5L5.5 9.5C4.67157 10.3284 4.67157 11.6716 5.5 12.5C6.32843 13.3284 7.67157 13.3284 8.5 12.5L13.5 7.5C14.8807 6.11929 14.8807 3.88071 13.5 2.5C12.1193 1.11929 9.88071 1.11929 8.5 2.5L3.5 7.5" stroke="currentColor" fill="none" stroke-width="1.2" stroke-linecap="round"/>`,
  },
  "code-lines": {
    viewBox: "0 0 16 16",
    body: `<path d="M4.5 5L2.5 7.5L4.5 10M11.5 5L13.5 7.5L11.5 10M9.5 3.5L6.5 12.5" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/>`,
  },
  glasses: {
    viewBox: "0 0 16 16",
    body: `<circle cx="4.5" cy="9.5" r="2.5" stroke="currentColor" fill="none" stroke-width="1.2"/><circle cx="11.5" cy="9.5" r="2.5" stroke="currentColor" fill="none" stroke-width="1.2"/><path d="M7 9.5H9M2 9.5L3.5 5.5M14 9.5L12.5 5.5" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/>`,
  },
  "bullet-list": {
    viewBox: "0 0 16 16",
    body: `<path d="M6 4.5H13.5M6 8H13.5M6 11.5H13.5M3 4.5H3.01M3 8H3.01M3 11.5H3.01" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>`,
  },
  "outline-dots": {
    viewBox: "0 0 16 16",
    body: `<path d="M2.5 7.5H3.5V8.5H2.5V7.5Z" stroke="currentColor"/><path d="M7.5 7.5H8.5V8.5H7.5V7.5Z" stroke="currentColor"/><path d="M12.5 7.5H13.5V8.5H12.5V7.5Z" stroke="currentColor"/>`,
  },
  "help-circle": {
    viewBox: "0 0 16 16",
    body: `<circle cx="8" cy="8" r="6" stroke="currentColor" fill="none" stroke-width="1.25"/><path d="M6.3 6C6.3 5.1 7.05 4.5 8 4.5C8.95 4.5 9.7 5.1 9.7 6C9.7 6.8 9 7.3 8.4 7.9C8.1 8.1 8 8.3 8 8.6V8.8M8 11.2H8.01" stroke="currentColor" stroke-width="1.25" stroke-linecap="round"/>`,
  },
  refresh: {
    viewBox: "0 0 16 16",
    body: `<path d="M2.5 8a5.5 5.5 0 0 1 9.78-3.82L13.5 5.5M13.5 2.5v3h-3M13.5 8a5.5 5.5 0 0 1-9.78 3.82L2.5 10.5M2.5 13.5v-3h3" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/>`,
  },
  warning: {
    viewBox: "0 0 16 16",
    body: `<path d="M8 1.5L15 13.5H1L8 1.5Z" stroke="currentColor" fill="none" stroke-width="1.25" stroke-linejoin="round"/><path d="M8 6.5V9.5M8 11.5H8.01" stroke="currentColor" stroke-width="1.25" stroke-linecap="round"/>`,
  },
  trash: {
    viewBox: "0 0 16 16",
    body: `<path d="M2.5 4.5H13.5M6 4.5V2.5H10V4.5M6.5 7.5V11.5M9.5 7.5V11.5M3.5 4.5L4 13.5H12L12.5 4.5" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/>`,
  },
  link: {
    viewBox: "0 0 16 16",
    body: `<path d="M6.5 9.5L9.5 6.5M6 4.5L6.8 3.7C7.9 2.6 9.6 2.6 10.7 3.7C11.8 4.8 11.8 6.5 10.7 7.6L9.9 8.4M10 11.5L9.2 12.3C8.1 13.4 6.4 13.4 5.3 12.3C4.2 11.2 4.2 9.5 5.3 8.4L6.1 7.6" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/>`,
  },
  "cloud-upload": {
    viewBox: "0 0 16 16",
    body: `<path d="M4.5 11.5C2.84315 11.5 1.5 10.1569 1.5 8.5C1.5 6.94465 2.68042 5.66301 4.19424 5.51496C4.51894 3.51584 6.25213 2 8.33333 2C10.6421 2 12.5217 3.85305 12.6653 6.17233C13.9755 6.51245 14.9444 7.71424 14.9444 9.14286C14.9444 10.7157 13.7113 12 12.1667 12H4.5Z" stroke="currentColor" fill="none" stroke-width="1.1" stroke-linejoin="round"/><path d="M8 12.5V7.5M8 7.5L6 9.5M8 7.5L10 9.5" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/>`,
  },
  "square-arrow-top-right": {
    viewBox: "0 0 16 16",
    body: `<path d="M5 11L11 5M11 5H6.5M11 5V9.5" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/>`,
  },
  "chevron-right": {
    viewBox: "0 0 16 16",
    body: `<path d="M6.5 4.5L10 8L6.5 11.5" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/>`,
  },
  "chevron-up": {
    viewBox: "0 0 16 16",
    body: `<path d="M4.5 9.5L8 6L11.5 9.5" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/>`,
  },
  "chevron-left": {
    viewBox: "0 0 16 16",
    body: `<path d="M9.5 4.5L6 8L9.5 11.5" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/>`,
  },
  "chevrons-left": {
    viewBox: "0 0 16 16",
    body: `<path d="M11.5 4.5L8 8L11.5 11.5M7.5 4.5L4 8L7.5 11.5" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/>`,
  },
  "chevrons-right": {
    viewBox: "0 0 16 16",
    body: `<path d="M4.5 4.5L8 8L4.5 11.5M8.5 4.5L12 8L8.5 11.5" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/>`,
  },
  "chevron-grabber-vertical": {
    viewBox: "0 0 16 16",
    body: `<path d="M5.5 5.5L8 3M8 3L10.5 5.5M5.5 10.5L8 13M8 13L10.5 10.5" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/>`,
  },
  "arrow-right": {
    viewBox: "0 0 16 16",
    body: `<path d="M2.5 8H13.5M13.5 8L9 3.5M13.5 8L9 12.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>`,
  },
  "arrow-left": {
    viewBox: "0 0 16 16",
    body: `<path d="M13.5 8H2.5M2.5 8L7 3.5M2.5 8L7 12.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>`,
  },
  "arrow-down": {
    viewBox: "0 0 16 16",
    body: `<path d="M8 2.5V13.5M8 13.5L3.5 9M8 13.5L12.5 9" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>`,
  },
  "arrow-down-to-line": {
    viewBox: "0 0 16 16",
    body: `<path d="M8 2.5V10.5M8 10.5L4.5 7M8 10.5L11.5 7M2.5 13.5H13.5" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/>`,
  },
  dash: {
    viewBox: "0 0 16 16",
    body: `<path d="M3.5 8H12.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>`,
  },
  "open-file": {
    viewBox: "0 0 16 16",
    body: `<path d="M2.5 4.5V12.5C2.5 13.05 2.95 13.5 3.5 13.5H12.5C13.05 13.5 13.5 13.05 13.5 12.5V6.5L10.5 3.5H3.5C2.95 3.5 2.5 3.95 2.5 4.5ZM10 3.5V6.5H13" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/>`,
  },
  pencil: {
    viewBox: "0 0 16 16",
    body: `<path d="M11.5 2.5L13.5 4.5L4.5 13.5H2.5V11.5L11.5 2.5Z" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/>`,
  },
  "pencil-line": {
    viewBox: "0 0 16 16",
    body: `<path d="M11.5 2.5L13.5 4.5L4.5 13.5H2.5V11.5L11.5 2.5Z" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/><path d="M2 14.5H14" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/>`,
  },
  // Documento con renglones y un destello: "redactar el informe con IA". El
  // destello es el mismo recurso visual que usa la industria para señalar una
  // acción asistida por modelo, así se entiende sin depender del tooltip.
  "report-sparkle": {
    viewBox: "0 0 16 16",
    body: `<path d="M9 1.5H4C3.44772 1.5 3 1.94772 3 2.5V13.5C3 14.0523 3.44772 14.5 4 14.5H11C11.5523 14.5 12 14.0523 12 13.5V4.5L9 1.5Z" stroke="currentColor" stroke-width="1.2" stroke-linejoin="round"/><path d="M8.75 1.75V4.25C8.75 4.66421 9.08579 5 9.5 5H11.75" stroke="currentColor" stroke-width="1.2" stroke-linejoin="round"/><path d="M5.25 7.75H8.25M5.25 10.25H7.25" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/><path d="M11.6 8.4L12.05 9.55L13.2 10L12.05 10.45L11.6 11.6L11.15 10.45L10 10L11.15 9.55L11.6 8.4Z" fill="currentColor" stroke="currentColor" stroke-width="0.5" stroke-linejoin="round"/>`,
  },
  "shield-check": {
    viewBox: "0 0 16 16",
    body: `<path d="M8 2L2.5 4.5V8.5C2.5 11.8 4.8 14.8 8 15.5C11.2 14.8 13.5 11.8 13.5 8.5V4.5L8 2Z" stroke="currentColor" fill="none" stroke-width="1.25"/><path d="M5.5 8.5L7.2 10.2L10.5 6.8" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/>`,
  },
  zap: {
    viewBox: "0 0 16 16",
    body: `<path d="M8.5 1.5L2.5 9H7.5L6.5 14.5L13.5 7H8.5L9.5 1.5Z" stroke="currentColor" fill="currentColor" fill-opacity="0.15" stroke-width="1.2" stroke-linejoin="round"/>`,
  },
  clipboard: {
    viewBox: "0 0 16 16",
    body: `<rect x="4.5" y="3.5" width="7" height="9.5" rx="1" stroke="currentColor" fill="none" stroke-width="1.2"/><path d="M6 3.5V2.5C6 2.22 6.22 2 6.5 2H9.5C9.78 2 10 2.22 10 2.5V3.5" stroke="currentColor" stroke-width="1.2"/>`,
  },
  eye: {
    viewBox: "0 0 16 16",
    body: `<path d="M2 8C2 8 4.5 3.5 8 3.5C11.5 3.5 14 8 14 8C14 8 11.5 12.5 8 12.5C4.5 12.5 2 8 2 8Z" stroke="currentColor" fill="none" stroke-width="1.2"/><circle cx="8" cy="8" r="2" stroke="currentColor" fill="none" stroke-width="1.2"/>`,
  },
  filter: {
    viewBox: "0 0 16 16",
    body: `<path d="M2.5 3.5H13.5L9 8.5V13L7 11.5V8.5L2.5 3.5Z" stroke="currentColor" fill="none" stroke-width="1.2" stroke-linejoin="round"/>`,
  },
  tag: {
    viewBox: "0 0 16 16",
    body: `<path d="M2.5 8.5L8.5 2.5H13.5V7.5L7.5 13.5L2.5 8.5Z" stroke="currentColor" fill="none" stroke-width="1.2" stroke-linejoin="round"/><circle cx="10.5" cy="5.5" r="1" fill="currentColor"/>`,
  },
}

export interface IconProps extends ComponentProps<"svg"> {
  name: keyof typeof icons | (string & {})
  size?: "small" | "normal" | "large"
  pixel?: boolean
}

export function Icon(props: IconProps) {
  const [split, rest] = splitProps(props, ["name", "size", "pixel"])
  const pixelSize = split.size === "small" ? 14 : split.size === "large" ? 20 : 16

  const raw = () => String(split.name ?? "").trim()
  const normalized = () => raw().replace(/\s+/g, "-").replace(/_/g, "-").toLowerCase()

  const strokeName = () => {
    const r = raw()
    if (icons[r as keyof typeof icons]) return r as keyof typeof icons
    const n = normalized()
    if (icons[n as keyof typeof icons]) return n as keyof typeof icons
    if (["memory", "memory-save", "memory-search", "memory-context", "context", "contexto"].includes(n)) return "brain"
    if (["web", "websearch", "web-search", "webfetch", "window-cursor", "discord"].includes(n)) return "globe"
    if (["shell", "bash", "command", "cmd", "enter"].includes(n)) return "terminal"
    if (["copy"].includes(n)) return "copy"
    if (["attach"].includes(n)) return "paperclip"
    if (["chat", "conversation", "message", "bubble-5", "question", "questions"].includes(n)) return "help-circle"
    if (["findings", "hallazgos"].includes(n)) return "shield-check"
    if (["reports", "reporte", "report", "printer"].includes(n)) return "checklist"
    if (["topology", "topologia", "network", "network-node"].includes(n)) return "server"
    if (["auditorias", "audits", "audit"].includes(n)) return "shield"
    if (["branch", "git-branch", "vcs", "code"].includes(n)) return "code-lines"
    if (["reset", "reload", "redo", "retry", "refresh-cw", "rotate-cw", "sync"].includes(n)) return "refresh"
    if (["sliders", "keyboard"].includes(n)) return "settings-gear"
    if (["outline-dots", "dots", "more"].includes(n)) return "dot-grid"
    if (["circle-ban-sign", "ban"].includes(n)) return "stop"
    if (["arrow-down-to-line"].includes(n)) return "arrow-down-to-line"
    if (["close-small"].includes(n)) return "close"
    if (["check", "circle-check", "selector"].includes(n)) return "check-small"
    if (["providers"].includes(n)) return "server"
    if (["models"].includes(n)) return "brain"
    if (["square-arrow-top-right", "external-link", "open-in-new", "external", "top-right"].includes(n)) return "square-arrow-top-right"
    if (["chevron-grabber-vertical", "grabber-vertical", "grabber"].includes(n)) return "chevron-grabber-vertical"
    if (["open-file", "file-open"].includes(n)) return "open-file"
    if (["pencil-line", "pencil", "rename"].includes(n)) return "pencil-line"
    if (["dash", "minus"].includes(n)) return "dash"
    if (n.includes("chevrons-right") || ["double-chevron-right", "expand-right"].includes(n)) return "chevrons-right"
    if (n.includes("chevrons-left") || ["double-chevron-left", "collapse-left"].includes(n)) return "chevrons-left"
    if (n.includes("chevron-right")) return "chevron-right"
    if (n.includes("chevron-up")) return "chevron-up"
    if (n.includes("chevron-left")) return "chevron-left"
    if (n.includes("chevron")) return "chevron-down"
    return undefined
  }

  // Si no se pide explícitamente pixel y hay ícono stroke disponible, usar stroke vectorizado (Regla V3/design.md §2)
  const resolvedStroke = strokeName()
  if (!split.pixel && resolvedStroke && icons[resolvedStroke]) {
    const icon = icons[resolvedStroke]
    return (
      <svg
        {...rest}
        data-slot="icon-svg"
        width={pixelSize}
        height={pixelSize}
        viewBox={icon.viewBox}
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        aria-hidden={rest["aria-hidden"] ?? "true"}
        innerHTML={icon.body}
        classList={{
          "shrink-0 inline-block align-middle": true,
          [String(rest.class ?? "")]: !!rest.class,
        }}
      />
    )
  }

  // Fallback a PIXEL_ICONS si no hay stroke o si se solicitó explícitamente
  const pixelData = () => {
    const r = raw()
    if (PIXEL_ICONS[r]) return PIXEL_ICONS[r]
    const n = normalized()
    if (PIXEL_ICONS[n]) return PIXEL_ICONS[n]
    if (["findings", "hallazgos"].includes(n)) return PIXEL_ICONS["shield-check"]
    if (["auditorias", "audits", "audit"].includes(n)) return PIXEL_ICONS["shield"]
    if (["reports", "reporte", "report"].includes(n)) return PIXEL_ICONS["checklist"]
    if (["topology", "topologia"].includes(n)) return PIXEL_ICONS["topology"]
    if (["chat", "conversation"].includes(n)) return PIXEL_ICONS["chat"]
    if (["memory", "memory-save", "memory-search"].includes(n)) return PIXEL_ICONS["database"]
    if (["shell", "bash", "command", "cmd"].includes(n)) return PIXEL_ICONS["terminal"]
    if (["close-small"].includes(n)) return PIXEL_ICONS["close"]
    if (["open-file", "file-open"].includes(n)) return PIXEL_ICONS["open-file"]
    return undefined
  }

  const pData = pixelData()
  if (pData) {
    return (
      <svg
        {...rest}
        data-slot="icon-svg"
        data-pixel="true"
        width={pixelSize}
        height={pixelSize}
        viewBox="0 0 32 32"
        fill="currentColor"
        xmlns="http://www.w3.org/2000/svg"
        aria-hidden={rest["aria-hidden"] ?? "true"}
        style={{
          "shape-rendering": "crispEdges",
          ...(typeof rest.style === "object" ? rest.style : {}),
        }}
        classList={{
          "shrink-0 inline-block align-middle": true,
          [String(rest.class ?? "")]: !!rest.class,
        }}
      >
        <path d={pData} fill="currentColor" />
      </svg>
    )
  }

  // Fallback final
  const fallback = icons["chevron-down"]
  return (
    <svg
      {...rest}
      data-slot="icon-svg"
      width={pixelSize}
      height={pixelSize}
      viewBox={fallback.viewBox}
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden={rest["aria-hidden"] ?? "true"}
      innerHTML={fallback.body}
      classList={{
        "shrink-0 inline-block align-middle": true,
        [String(rest.class ?? "")]: !!rest.class,
      }}
    />
  )
}

