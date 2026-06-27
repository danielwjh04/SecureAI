import { renderHook } from '@testing-library/react'
import { useScrollToTopOnChange } from './useScrollToTopOnChange'

describe('useScrollToTopOnChange', () => {
  it('scrolls to the top on mount', () => {
    const scrollTo = vi.spyOn(window, 'scrollTo').mockImplementation(() => {})

    renderHook(() => useScrollToTopOnChange('hash-1'))

    expect(scrollTo).toHaveBeenCalledWith({ top: 0, left: 0, behavior: 'auto' })
    scrollTo.mockRestore()
  })

  it('scrolls again only when the key changes', () => {
    const scrollTo = vi.spyOn(window, 'scrollTo').mockImplementation(() => {})
    const { rerender } = renderHook(({ k }) => useScrollToTopOnChange(k), {
      initialProps: { k: 'hash-1' },
    })
    expect(scrollTo).toHaveBeenCalledTimes(1)

    // Same result re-rendered: no extra scroll.
    rerender({ k: 'hash-1' })
    expect(scrollTo).toHaveBeenCalledTimes(1)

    // A different report (new head hash) replaces it: scroll back to the top.
    rerender({ k: 'hash-2' })
    expect(scrollTo).toHaveBeenCalledTimes(2)
    scrollTo.mockRestore()
  })
})
