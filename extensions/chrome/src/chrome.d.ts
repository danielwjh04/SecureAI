declare namespace chrome {
  namespace runtime {
    interface MessageSender {
      tab?: { id?: number; url?: string }
      url?: string
    }

    const onInstalled: {
      addListener(callback: () => void): void
    }

    const onMessage: {
      addListener(
        callback: (
          message: unknown,
          sender: MessageSender,
          sendResponse: (response?: unknown) => void,
        ) => boolean | void,
      ): void
    }

    function sendMessage<T = unknown>(message: unknown): Promise<T>
  }

  namespace storage {
    interface StorageArea {
      get(keys?: string | string[] | Record<string, unknown> | null): Promise<Record<string, unknown>>
      set(items: Record<string, unknown>): Promise<void>
    }

    const local: StorageArea
  }

  namespace declarativeNetRequest {
    type RuleActionType = 'block'

    interface RuleAction {
      type: RuleActionType
    }

    interface RuleCondition {
      urlFilter?: string
      resourceTypes?: string[]
    }

    interface Rule {
      id: number
      priority: number
      action: RuleAction
      condition: RuleCondition
    }

    function updateDynamicRules(update: {
      addRules?: Rule[]
      removeRuleIds?: number[]
    }): Promise<void>

    function getDynamicRules(): Promise<Rule[]>
  }

  namespace contextMenus {
    interface CreateProperties {
      id: string
      title: string
      contexts: string[]
      documentUrlPatterns?: string[]
      targetUrlPatterns?: string[]
    }

    const onClicked: {
      addListener(callback: (info: { menuItemId?: string; linkUrl?: string; selectionText?: string }) => void): void
    }

    function create(properties: CreateProperties): void
    function removeAll(callback?: () => void): void
  }

  namespace tabs {
    function sendMessage(tabId: number, message: unknown): Promise<unknown>
  }
}
