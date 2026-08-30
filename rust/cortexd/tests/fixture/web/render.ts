export interface Frame {
  width: number;
}

export function render(frame: Frame): string {
  return `frame:${frame.width}`;
}
