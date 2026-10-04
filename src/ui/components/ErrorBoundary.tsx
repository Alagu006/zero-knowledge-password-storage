import React, { Component, ErrorInfo, ReactNode } from "react";
import { Error5xxPage } from "./Error5xxPage";

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error("UI Uncaught Error:", error, errorInfo);
  }

  public render() {
    if (this.state.hasError) {
      return (
        <Error5xxPage
          code={500}
          title="APPLICATION NEURAL CRASH"
          message="A component runtime error interrupted the client interface. The zero-trust sandbox halted execution to protect in-memory cryptographic keys."
          error={this.state.error}
        />
      );
    }

    return this.props.children;
  }
}
