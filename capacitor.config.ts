import type { CapacitorConfig } from "@capacitor/cli";

const config: CapacitorConfig = {
  appId: "app.aegis.scanner",
  appName: "Aegis",
  webDir: "dist",
  android: {
    allowMixedContent: true,
  },
};

export default config;
