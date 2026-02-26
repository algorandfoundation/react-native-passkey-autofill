import { NativeModule, requireNativeModule } from 'expo';

import { ReactNativeLiquidAuthModuleEvents } from './ReactNativeLiquidAuth.types';

declare class ReactNativeLiquidAuthModule extends NativeModule<ReactNativeLiquidAuthModuleEvents> {
  PI: number;
  hello(): string;
  setValueAsync(value: string): Promise<void>;
}

// This call loads the native module object from the JSI.
export default requireNativeModule<ReactNativeLiquidAuthModule>('ReactNativeLiquidAuth');
