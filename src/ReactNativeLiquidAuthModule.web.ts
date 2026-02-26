import { registerWebModule, NativeModule } from 'expo';

import { ReactNativeLiquidAuthModuleEvents } from './ReactNativeLiquidAuth.types';

class ReactNativeLiquidAuthModule extends NativeModule<ReactNativeLiquidAuthModuleEvents> {
  PI = Math.PI;
  async setValueAsync(value: string): Promise<void> {
    this.emit('onChange', { value });
  }
  hello() {
    return 'Hello world! 👋';
  }
}

export default registerWebModule(ReactNativeLiquidAuthModule, 'ReactNativeLiquidAuthModule');
