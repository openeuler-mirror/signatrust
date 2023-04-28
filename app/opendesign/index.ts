import type { App } from 'vue';

import './style/variable.scss';

import { Button } from './button';
import { Icon } from './icon';
import { Tabs, TabPane } from './tabs';
import { Input } from './input';
import { Checkbox, CheckboxGroup } from './checkbox';
import { Switch } from './switch';

const components = [
  Button,
  Checkbox,
  CheckboxGroup,
  Icon,
  Input,
  Tabs,
  TabPane,
  Switch,
];
export default {
  install(app: App): void {
    components.forEach((component) => {
      app.use(component as any);
    });
  },
};
