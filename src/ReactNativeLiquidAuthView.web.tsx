import * as React from 'react';

import { ReactNativeLiquidAuthViewProps } from './ReactNativeLiquidAuth.types';

export default function ReactNativeLiquidAuthView(props: ReactNativeLiquidAuthViewProps) {
  return (
    <div>
      <iframe
        style={{ flex: 1 }}
        src={props.url}
        onLoad={() => props.onLoad({ nativeEvent: { url: props.url } })}
      />
    </div>
  );
}
