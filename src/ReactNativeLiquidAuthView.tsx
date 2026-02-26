import { requireNativeView } from 'expo';
import * as React from 'react';

import { ReactNativeLiquidAuthViewProps } from './ReactNativeLiquidAuth.types';

const NativeView: React.ComponentType<ReactNativeLiquidAuthViewProps> =
  requireNativeView('ReactNativeLiquidAuth');

export default function ReactNativeLiquidAuthView(props: ReactNativeLiquidAuthViewProps) {
  return <NativeView {...props} />;
}
