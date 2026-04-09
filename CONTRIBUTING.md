# 🤝 Contributing

Contributions are very welcome! Whether you are fixing a bug, adding a feature, or improving documentation, your help is appreciated.

## Getting Started

To get started with the project, follow these steps:

1. **Fork the repository** to your own GitHub account.
2. **Clone the repository** to your local machine.
3. **Install dependencies** at the root of the project:
   ```bash
   pnpm install
   ```
4. **Build the project**:
   ```bash
   pnpm run build
   ```

## Development Workflow

### Example App

The project includes an example app in the `example/` directory. You can use it to test your changes.

1. Navigate to the `example/` directory:
   ```bash
   cd example
   ```
2. Install example dependencies:
   ```bash
   pnpm install
   ```
3. Prebuild the example for Android or iOS:
   ```bash
   npx expo prebuild
   ```
4. Run the example app:
   ```bash
   pnpm run android # for Android
   # or
   pnpm run ios # for iOS
   ```

### Code Style

- Use Prettier for code formatting (run `npx prettier --write .` if available).
- Follow existing naming conventions and patterns in the codebase.
- Ensure all TypeScript types are correctly defined.

For more details on how the project is structured, see the [Architecture Guide](./ARCHITECTURE.md).

### Testing

Before submitting a Pull Request, ensure that both JavaScript and Native tests pass:

```bash
pnpm run test:all
```

For more details on the testing strategy, refer to the [Testing section in README.md](./README.md#🧪-testing).

## Submitting a Pull Request

1. Create a new branch for your feature or bugfix:
   ```bash
   git checkout -b feature/your-feature-name
   ```
2. Make your changes and commit them with a descriptive message.
3. Push your branch to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```
4. Open a Pull Request on the main repository.

## Reporting Issues

If you find a bug or have a feature request, please open an issue on the GitHub repository. Provide as much detail as possible, including steps to reproduce the issue.

---

Thank you for contributing!
