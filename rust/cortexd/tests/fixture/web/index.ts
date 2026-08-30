import { render } from './render';

export function page(): string {
  return render({ width: 3 });
}
