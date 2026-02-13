import { useState, useEffect } from 'react'
import './index.css'
import { HomeIcon, FriendsIcon, SettingsIcon } from './icons'
import { API_BASE_URL } from './config'
import logoSvg from '/logo.svg'

// Types matching backend response shapes
interface Transaction {
  id: string
  type: 'DEPOSIT' | 'WITHDRAW' | 'TRANSFER'
  direction: 'sent' | 'received'
  amount: number
  sender?: { id: string; displayName: string; type: string }
  receiver?: { id: string; displayName: string; type: string }
  createdAt: string
  status: string
  memo?: string
  metadata?: { isRequest?: boolean; requestedBy?: string } | null
}

interface IncomingRequest {
  id: string
  amount: number
  requestedBy: { id: string; displayName: string }
  memo?: string
  createdAt: string
}

interface User {
  id: string
  displayName: string
  email?: string
  type: string
  walletAddress?: string
}

interface Wallet {
  publicKey: string
  usdcBalance: number
  solBalance: number
  isActive: boolean
}

interface BankAccount {
  id: string
  bankName: string
  accountType: 'CHECKING' | 'SAVINGS'
  accountLast4: string
  routingLast4: string
  isDefault: boolean
  createdAt: string
}


function App() {
  // Auth state
  const [token, setToken] = useState<string | null>(localStorage.getItem('agentpay_token'))
  const [user, setUser] = useState<User | null>(null)
  const [wallet, setWallet] = useState<Wallet | null>(null)
  
  // UI state
  const [activeTab, setActiveTab] = useState<'home' | 'friends' | 'settings'>('home')
  const [showSendModal, setShowSendModal] = useState(false)
  const [showRequestModal, setShowRequestModal] = useState(false)
  const [showDepositModal, setShowDepositModal] = useState(false)
  const [showWithdrawModal, setShowWithdrawModal] = useState(false)
  const [showBankModal, setShowBankModal] = useState(false)
  const [authMode, setAuthMode] = useState<'login' | 'register'>('login')
  const [show2FASetup, setShow2FASetup] = useState(false)
  const [qrCodeUrl, setQrCodeUrl] = useState<string | null>(null)
  const [totpManualSecret, setTotpManualSecret] = useState<string | null>(null)
  const [totpCode, setTotpCode] = useState('')
  const [requiresTotpCode, setRequiresTotpCode] = useState(false)
  const [tempToken, setTempToken] = useState<string | null>(null)
  
  // Data state
  const [transactions, setTransactions] = useState<Transaction[]>([])
  const [incomingRequests, setIncomingRequests] = useState<IncomingRequest[]>([])
  const [bankAccounts, setBankAccounts] = useState<BankAccount[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  
  // Form state
  const [loginEmail, setLoginEmail] = useState('')
  const [loginPassword, setLoginPassword] = useState('')
  const [registerEmail, setRegisterEmail] = useState('')
  const [registerPassword, setRegisterPassword] = useState('')
  const [registerName, setRegisterName] = useState('')
  const [sendRecipient, setSendRecipient] = useState('')
  const [sendRecipientName, setSendRecipientName] = useState('')
  const [sendSearch, setSendSearch] = useState('')
  const [sendSearchResults, setSendSearchResults] = useState<Array<{id: string, displayName: string, type: string}>>([])
  const [sendAmount, setSendAmount] = useState('')
  const [sendMemo, setSendMemo] = useState('')
  const [requestRecipient, setRequestRecipient] = useState('')
  const [requestRecipientName, setRequestRecipientName] = useState('')
  const [requestSearch, setRequestSearch] = useState('')
  const [requestSearchResults, setRequestSearchResults] = useState<Array<{id: string, displayName: string, type: string}>>([])
  const [requestAmount, setRequestAmount] = useState('')
  const [requestMemo, setRequestMemo] = useState('')
  const [depositAmount, setDepositAmount] = useState('10')
  const [withdrawAddress, setWithdrawAddress] = useState('')
  const [withdrawAmount, setWithdrawAmount] = useState('')
  const [withdrawMemo, setWithdrawMemo] = useState('')
  const [editDisplayName, setEditDisplayName] = useState('')
  const [editDailyLimit, setEditDailyLimit] = useState('')
  const [editTxLimit, setEditTxLimit] = useState('')
  const [settingsSuccess, setSettingsSuccess] = useState<string | null>(null)
  const [bankName, setBankName] = useState('')
  const [bankAccountType, setBankAccountType] = useState<'CHECKING' | 'SAVINGS'>('CHECKING')
  const [bankAccountNumber, setBankAccountNumber] = useState('')
  const [bankRoutingNumber, setBankRoutingNumber] = useState('')

  // Friends state
  const [friends, setFriends] = useState<Array<{id: string, displayName: string, type: string, walletAddress?: string, addedAt?: string}>>([])
  const [friendRequests, setFriendRequests] = useState<Array<{id: string, from: {id: string, displayName: string, type: string, walletAddress?: string}, createdAt: string}>>([])
  const [searchQuery, setSearchQuery] = useState('')
  const [searchResults, setSearchResults] = useState<Array<{id: string, displayName: string, type: string, walletAddress?: string}>>([])
  const [pendingSentIds, setPendingSentIds] = useState<Set<string>>(new Set())
  const [isSearching, setIsSearching] = useState(false)
  const [toast, setToast] = useState<string | null>(null)
  const [refreshing, setRefreshing] = useState(false)

  // Load user data on mount if token exists
  useEffect(() => {
    if (token) {
      fetchUser()
      fetchWallet()
      fetchTransactions()
      fetchIncomingRequests()
      fetchBankAccounts()
      fetchFriends()
      fetchFriendRequests()
    }
  }, [token])

  // Debounced search (friends tab)
  useEffect(() => {
    const timer = setTimeout(() => {
      if (searchQuery.trim()) {
        searchUsers(searchQuery)
      } else {
        setSearchResults([])
      }
    }, 300)
    return () => clearTimeout(timer)
  }, [searchQuery, friends])

  // Debounced search (send modal)
  useEffect(() => {
    const timer = setTimeout(async () => {
      if (sendSearch.trim() && !sendRecipient) {
        try {
          const data = await apiFetch(`/users/search/query?q=${encodeURIComponent(sendSearch)}&limit=5`)
          setSendSearchResults((data.users || []).filter((u: any) => u.id !== user?.id))
        } catch { setSendSearchResults([]) }
      } else {
        setSendSearchResults([])
      }
    }, 300)
    return () => clearTimeout(timer)
  }, [sendSearch])

  // Debounced search (request modal)
  useEffect(() => {
    const timer = setTimeout(async () => {
      if (requestSearch.trim() && !requestRecipient) {
        try {
          const data = await apiFetch(`/users/search/query?q=${encodeURIComponent(requestSearch)}&limit=5`)
          setRequestSearchResults((data.users || []).filter((u: any) => u.id !== user?.id))
        } catch { setRequestSearchResults([]) }
      } else {
        setRequestSearchResults([])
      }
    }, 300)
    return () => clearTimeout(timer)
  }, [requestSearch])

  // API calls
  const apiFetch = async (endpoint: string, options: RequestInit = {}) => {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    }

    if (token) {
      headers['Authorization'] = `Bearer ${token}`
    }

    // Explicit headers override defaults (e.g. setup2FA passes its own auth token)
    Object.assign(headers, options.headers as Record<string, string>)
    
    const response = await fetch(`${API_BASE_URL}/api${endpoint}`, {
      ...options,
      headers
    })
    
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({ error: 'Unknown error' }))
      throw new Error(errorData.error || `HTTP ${response.status}`)
    }
    
    return response.json()
  }

  const fetchUser = async () => {
    try {
      const data = await apiFetch('/users/me')
      setUser(data)
    } catch (err) {
      console.error('Failed to fetch user:', err)
    }
  }

  const fetchWallet = async () => {
    try {
      const data = await apiFetch('/wallets/me')
      setWallet(data)
    } catch (err) {
      console.error('Failed to fetch wallet:', err)
    }
  }

  const fetchTransactions = async () => {
    try {
      const data = await apiFetch('/transactions')
      setTransactions(data.transactions || [])
    } catch (err) {
      console.error('Failed to fetch transactions:', err)
    }
  }

  const fetchIncomingRequests = async () => {
    try {
      const data = await apiFetch('/transfers/requests/incoming')
      setIncomingRequests(data.requests || [])
    } catch (err) {
      console.error('Failed to fetch incoming requests:', err)
    }
  }

  const handleAcceptPaymentRequest = async (requestId: string) => {
    setLoading(true)
    setError(null)
    try {
      await apiFetch(`/transfers/requests/${requestId}/accept`, { method: 'POST' })
      await Promise.all([fetchWallet(), fetchTransactions(), fetchIncomingRequests()])
    } catch (err: any) {
      setError(err.message || 'Failed to accept request')
    } finally {
      setLoading(false)
    }
  }

  const handleDismissPaymentRequest = async (requestId: string) => {
    setLoading(true)
    setError(null)
    try {
      await apiFetch(`/transfers/requests/${requestId}/dismiss`, { method: 'POST' })
      await Promise.all([fetchTransactions(), fetchIncomingRequests()])
    } catch (err: any) {
      setError(err.message || 'Failed to dismiss request')
    } finally {
      setLoading(false)
    }
  }

  const fetchBankAccounts = async () => {
    try {
      const data = await apiFetch('/banks')
      setBankAccounts(data.bankAccounts || [])
    } catch (err) {
      console.error('Failed to fetch bank accounts:', err)
    }
  }

  const fetchFriends = async () => {
    try {
      const data = await apiFetch('/friends')
      setFriends(data.friends || [])
    } catch (err) {
      console.error('Failed to fetch friends:', err)
    }
  }

  const fetchFriendRequests = async () => {
    try {
      const data = await apiFetch('/friends/requests')
      setFriendRequests(data.requests || [])
    } catch (err) {
      console.error('Failed to fetch friend requests:', err)
    }
  }

  const handleAcceptRequest = async (requestId: string) => {
    try {
      await apiFetch(`/friends/${requestId}/accept`, { method: 'POST' })
      await fetchFriends()
      await fetchFriendRequests()
    } catch (err: any) {
      setError(err.message || 'Failed to accept request')
    }
  }

  const handleDeclineRequest = async (requestId: string) => {
    try {
      await apiFetch(`/friends/${requestId}/decline`, { method: 'POST' })
      await fetchFriendRequests()
    } catch (err: any) {
      setError(err.message || 'Failed to decline request')
    }
  }

  const searchUsers = async (query: string) => {
    if (!query.trim()) {
      setSearchResults([])
      return
    }
    setIsSearching(true)
    try {
      const data = await apiFetch(`/users/search/query?q=${encodeURIComponent(query)}&limit=10`)
      // Filter out users who are already friends
      const friendIds = new Set(friends.map(f => f.id))
      const filtered = (data.users || []).filter((u: any) => !friendIds.has(u.id) && u.id !== user?.id)
      setSearchResults(filtered)
    } catch (err) {
      console.error('Failed to search users:', err)
      setSearchResults([])
    } finally {
      setIsSearching(false)
    }
  }

  const handleAddFriend = async (friendId: string) => {
    setLoading(true)
    setError(null)
    try {
      await apiFetch('/friends', {
        method: 'POST',
        body: JSON.stringify({ friendId })
      })
      setPendingSentIds(prev => new Set([...prev, friendId]))
      setToast('Friend request sent!')
      setTimeout(() => setToast(null), 2500)
    } catch (err: any) {
      setError(err.message || 'Failed to send request')
    } finally {
      setLoading(false)
    }
  }

  const handleRemoveFriend = async (friendId: string) => {
    try {
      await apiFetch(`/friends/${friendId}`, { method: 'DELETE' })
      await fetchFriends()
    } catch (err: any) {
      setError(err.message || 'Failed to remove friend')
    }
  }

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError(null)

    try {
      const data = await apiFetch('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email: loginEmail, password: loginPassword })
      })

      if (data.requiresTotpSetup) {
        // First login — need to set up 2FA
        localStorage.setItem('agentpay_token', data.token)
        setToken(data.token)
        setUser(data.user)
        await setup2FA(data.token)
      } else if (data.requiresTotpCode) {
        // 2FA enabled — need code
        setRequiresTotpCode(true)
        setTempToken(data.tempToken)
      }
    } catch (err: any) {
      setError(err.message || 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  const setup2FA = async (authToken?: string) => {
    try {
      const t = authToken || token
      const data = await apiFetch('/auth/totp/setup', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${t}` },
      })
      setQrCodeUrl(data.qrCodeDataUrl)
      setTotpManualSecret(data.secret)
      setShow2FASetup(true)
    } catch (err: any) {
      setError(err.message || '2FA setup failed')
    }
  }

  const verify2FASetup = async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await apiFetch('/auth/totp/verify', {
        method: 'POST',
        body: JSON.stringify({ code: totpCode }),
      })
      localStorage.setItem('agentpay_token', data.token)
      setToken(data.token)
      setUser(data.user)
      setShow2FASetup(false)
      setTotpCode('')
      setQrCodeUrl(null)
      setTotpManualSecret(null)
      await Promise.all([fetchWallet(), fetchTransactions(), fetchBankAccounts(), fetchFriends(), fetchFriendRequests()])
    } catch (err: any) {
      setError(err.message || 'Invalid code')
    } finally {
      setLoading(false)
    }
  }

  const verify2FALogin = async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await apiFetch('/auth/totp/verify', {
        method: 'POST',
        body: JSON.stringify({ code: totpCode, tempToken }),
      })
      localStorage.setItem('agentpay_token', data.token)
      setToken(data.token)
      setUser(data.user)
      setRequiresTotpCode(false)
      setTempToken(null)
      setTotpCode('')
      await Promise.all([fetchWallet(), fetchTransactions(), fetchBankAccounts(), fetchFriends(), fetchFriendRequests()])
    } catch (err: any) {
      setError(err.message || 'Invalid code')
    } finally {
      setLoading(false)
    }
  }

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError(null)

    try {
      const data = await apiFetch('/auth/register/human', {
        method: 'POST',
        body: JSON.stringify({
          email: registerEmail,
          password: registerPassword,
          displayName: registerName
        })
      })

      localStorage.setItem('agentpay_token', data.token)
      setToken(data.token)
      setUser(data.user)
      if (data.requiresTotpSetup) {
        await setup2FA(data.token)
      }
    } catch (err: any) {
      setError(err.message || 'Registration failed')
    } finally {
      setLoading(false)
    }
  }

  const handleSend = async (e: React.FormEvent) => {
    e.preventDefault()
    if ((!sendRecipient && !sendSearch.trim()) || !sendAmount) return

    setLoading(true)
    setError(null)

    try {
      const body: any = {
        amount: parseFloat(sendAmount),
        memo: sendMemo || undefined
      }
      if (sendRecipient) {
        body.toUserId = sendRecipient
      } else {
        body.toUsername = sendSearch.trim()
      }

      // Use demo-send in dev mode (cached balances), real send in production
      const endpoint = import.meta.env.DEV ? '/transfers/demo-send' : '/transfers/send'
      await apiFetch(endpoint, {
        method: 'POST',
        body: JSON.stringify(body)
      })

      // Refresh data
      await fetchWallet()
      await fetchTransactions()

      // Reset form
      setSendRecipient('')
      setSendRecipientName('')
      setSendSearch('')
      setSendSearchResults([])
      setSendAmount('')
      setSendMemo('')
      setShowSendModal(false)
    } catch (err: any) {
      setError(err.message || 'Transfer failed')
    } finally {
      setLoading(false)
    }
  }

  const handleRequest = async (e: React.FormEvent) => {
    e.preventDefault()
    if ((!requestRecipient && !requestSearch.trim()) || !requestAmount) return
    setLoading(true)
    setError(null)
    try {
      const body: any = {
        amount: parseFloat(requestAmount),
        memo: requestMemo || undefined
      }
      if (requestRecipient) {
        body.fromUserId = requestRecipient
      } else {
        body.fromUsername = requestSearch.trim()
      }
      await apiFetch('/transfers/request', {
        method: 'POST',
        body: JSON.stringify(body)
      })
      await fetchTransactions()
      setRequestRecipient('')
      setRequestRecipientName('')
      setRequestSearch('')
      setRequestSearchResults([])
      setRequestAmount('')
      setRequestMemo('')
      setShowRequestModal(false)
    } catch (err: any) {
      setError(err.message || 'Request failed')
    } finally {
      setLoading(false)
    }
  }

  const handleDeposit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError(null)
    try {
      await apiFetch('/wallets/deposit', {
        method: 'POST',
        body: JSON.stringify({ amount: parseFloat(depositAmount) || 10 })
      })
      await fetchWallet()
      await fetchTransactions()
      setDepositAmount('10')
      setShowDepositModal(false)
    } catch (err: any) {
      setError(err.message || 'Deposit failed')
    } finally {
      setLoading(false)
    }
  }

  const handleWithdraw = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!withdrawAddress || !withdrawAmount) return
    setLoading(true)
    setError(null)
    try {
      await apiFetch('/transfers/withdraw', {
        method: 'POST',
        body: JSON.stringify({
          toWalletAddress: withdrawAddress,
          amount: parseFloat(withdrawAmount),
          memo: withdrawMemo || undefined
        })
      })
      await fetchWallet()
      await fetchTransactions()
      setWithdrawAddress('')
      setWithdrawAmount('')
      setWithdrawMemo('')
      setShowWithdrawModal(false)
    } catch (err: any) {
      setError(err.message || 'Withdrawal failed')
    } finally {
      setLoading(false)
    }
  }

  const handleConnectBank = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!bankName || !bankAccountNumber || !bankRoutingNumber) return
    setLoading(true)
    setError(null)
    try {
      await apiFetch('/banks', {
        method: 'POST',
        body: JSON.stringify({
          bankName,
          accountType: bankAccountType,
          accountNumber: bankAccountNumber,
          routingNumber: bankRoutingNumber,
        })
      })
      await fetchBankAccounts()
      setBankName('')
      setBankAccountNumber('')
      setBankRoutingNumber('')
      setShowBankModal(false)
      setSettingsSuccess('Bank account connected!')
    } catch (err: any) {
      setError(err.message || 'Failed to connect bank')
    } finally {
      setLoading(false)
    }
  }

  const handleRemoveBank = async (bankId: string) => {
    try {
      await apiFetch(`/banks/${bankId}`, { method: 'DELETE' })
      await fetchBankAccounts()
    } catch (err: any) {
      setError(err.message || 'Failed to remove bank')
    }
  }

  const handleUpdateSettings = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError(null)
    setSettingsSuccess(null)
    try {
      const updates: Record<string, any> = {}
      if (editDisplayName) updates.displayName = editDisplayName
      if (editDailyLimit) updates.dailyLimit = parseFloat(editDailyLimit) || null
      if (editTxLimit) updates.txLimit = parseFloat(editTxLimit) || null
      if (Object.keys(updates).length === 0) return
      const data = await apiFetch('/users/me', {
        method: 'PATCH',
        body: JSON.stringify(updates)
      })
      if (data.displayName && user) {
        setUser({ ...user, displayName: data.displayName })
      }
      setSettingsSuccess('Settings updated!')
      setEditDisplayName('')
      setEditDailyLimit('')
      setEditTxLimit('')
    } catch (err: any) {
      setError(err.message || 'Update failed')
    } finally {
      setLoading(false)
    }
  }

  const handleLogout = () => {
    localStorage.removeItem('agentpay_token')
    setToken(null)
    setUser(null)
    setWallet(null)
    setTransactions([])
    setShow2FASetup(false)
    setRequiresTotpCode(false)
    setTempToken(null)
    setTotpCode('')
  }


  // Helpers
  const formatBalance = (amount: number) => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD'
    }).format(amount)
  }

  const formatTime = (dateStr: string) => {
    return new Intl.DateTimeFormat('en-US', {
      month: 'short',
      day: 'numeric',
      hour: 'numeric',
      minute: '2-digit'
    }).format(new Date(dateStr))
  }

  const isRequest = (tx: Transaction) => tx.metadata?.isRequest === true

  const getDisplayType = (tx: Transaction) => {
    if (tx.type === 'DEPOSIT') return 'deposit'
    if (tx.type === 'WITHDRAW') return 'withdraw'
    return tx.direction // 'sent' or 'received'
  }

  const getTransactionIcon = (tx: Transaction) => {
    if (isRequest(tx) && tx.status === 'PENDING') return '⏳'
    if (isRequest(tx) && tx.status === 'CANCELLED') return '✕'
    const dt = getDisplayType(tx)
    switch (dt) {
      case 'received': return '↓'
      case 'sent': return '↑'
      case 'deposit': return '💰'
      case 'withdraw': return '💸'
      default: return '•'
    }
  }

  const getTransactionColor = (tx: Transaction) => {
    if (isRequest(tx) && tx.status === 'PENDING') return 'bg-yellow-500'
    if (isRequest(tx) && tx.status === 'CANCELLED') return 'bg-gray-400'
    const dt = getDisplayType(tx)
    switch (dt) {
      case 'received': return 'bg-green-500'
      case 'sent': return 'bg-red-500'
      case 'deposit': return 'bg-twitter-blue'
      case 'withdraw': return 'bg-orange-500'
      default: return 'bg-gray-500'
    }
  }

  const getTransactionLabel = (tx: Transaction) => {
    if (isRequest(tx)) {
      if (tx.status === 'PENDING') {
        return tx.direction === 'sent'
          ? `Request from @${tx.receiver?.displayName || 'Unknown'}`
          : `Requested from @${tx.sender?.displayName || 'Unknown'}`
      }
      if (tx.status === 'CANCELLED') {
        return tx.direction === 'sent'
          ? `Dismissed request from @${tx.receiver?.displayName || 'Unknown'}`
          : `Request dismissed by @${tx.sender?.displayName || 'Unknown'}`
      }
      // CONFIRMED request = paid
      return tx.direction === 'sent'
        ? `Paid request to @${tx.receiver?.displayName || 'Unknown'}`
        : `Received (requested) from @${tx.sender?.displayName || 'Unknown'}`
    }
    const dt = getDisplayType(tx)
    switch (dt) {
      case 'received': return `From @${tx.sender?.displayName || 'Unknown'}`
      case 'sent': return `To @${tx.receiver?.displayName || 'Unknown'}`
      case 'deposit': return 'Deposit'
      case 'withdraw': return 'Withdrawal'
      default: return 'Transaction'
    }
  }

  const getStatusBadge = (tx: Transaction) => {
    if (!isRequest(tx)) return null
    if (tx.status === 'PENDING') return { text: 'Pending', color: 'bg-yellow-100 text-yellow-700' }
    if (tx.status === 'CANCELLED') return { text: 'Dismissed', color: 'bg-gray-100 text-gray-500' }
    return { text: 'Paid', color: 'bg-green-100 text-green-700' }
  }

  const isPositive = (tx: Transaction) => {
    // Pending requests haven't moved money yet
    if (isRequest(tx) && tx.status === 'PENDING') return false
    if (isRequest(tx) && tx.status === 'CANCELLED') return false
    const dt = getDisplayType(tx)
    return dt === 'received' || dt === 'deposit'
  }

  // 2FA Setup Modal (after registration or first login)
  if (show2FASetup) {
    return (
      <div className="min-h-screen bg-twitter-gray-lightest flex items-center justify-center p-4">
        <div className="bg-white rounded-2xl p-8 w-full max-w-md shadow-lg">
          <div className="text-center mb-6">
            <div className="flex items-center justify-center gap-3 mb-2">
              <img src={logoSvg} alt="AgentPay" className="w-10 h-10" />
              <h1 className="text-3xl font-semibold text-twitter-blue tracking-tight" style={{ fontFamily: 'system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif' }}>AgentPay</h1>
            </div>
            <p className="text-twitter-gray">Set Up Two-Factor Authentication</p>
          </div>
          <p className="text-center text-twitter-gray mb-4 text-sm">
            Scan this QR code with Google Authenticator (or any TOTP app), then enter the 6-digit code to verify.
          </p>
          {qrCodeUrl && (
            <div className="flex justify-center mb-4">
              <img src={qrCodeUrl} alt="2FA QR Code" className="w-48 h-48 rounded-lg border border-twitter-gray-lighter" />
            </div>
          )}
          {totpManualSecret && (
            <div className="bg-twitter-gray-lightest p-3 rounded-lg mb-4 text-center">
              <div className="text-xs text-twitter-gray mb-1">Manual entry key:</div>
              <div className="font-mono text-sm font-bold tracking-wider select-all break-all">{totpManualSecret}</div>
            </div>
          )}
          {error && <div className="bg-red-100 text-red-600 p-3 rounded-lg mb-4 text-sm">{error}</div>}
          <div className="space-y-4">
            <input
              type="text"
              value={totpCode}
              onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
              placeholder="000000"
              maxLength={6}
              className="w-full p-4 border border-twitter-gray-lighter rounded-lg focus:outline-none focus:border-twitter-blue text-center text-3xl font-bold tracking-widest font-mono"
            />
            <button
              onClick={verify2FASetup}
              disabled={loading || totpCode.length !== 6}
              className="w-full bg-twitter-blue hover:bg-twitter-blue-dark text-white py-3 rounded-full font-semibold transition-colors disabled:opacity-50"
            >
              {loading ? 'Verifying...' : 'Verify & Enable 2FA'}
            </button>
          </div>
          <div className="mt-4 p-3 bg-yellow-50 border border-yellow-200 rounded-lg">
            <p className="text-xs text-yellow-800 text-center font-medium">
              There is no password reset. Keep your authenticator app secure — it's your only way to log in.
            </p>
          </div>
        </div>
      </div>
    )
  }

  // 2FA Login Verification (returning user with TOTP enabled)
  if (requiresTotpCode) {
    return (
      <div className="min-h-screen bg-twitter-gray-lightest flex items-center justify-center p-4">
        <div className="bg-white rounded-2xl p-8 w-full max-w-md shadow-lg">
          <div className="text-center mb-6">
            <div className="flex items-center justify-center gap-3 mb-2">
              <img src={logoSvg} alt="AgentPay" className="w-10 h-10" />
              <h1 className="text-3xl font-semibold text-twitter-blue tracking-tight" style={{ fontFamily: 'system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif' }}>AgentPay</h1>
            </div>
            <p className="text-twitter-gray">Enter Authentication Code</p>
          </div>
          <p className="text-center text-twitter-gray mb-6 text-sm">
            Open your authenticator app and enter the 6-digit code.
          </p>
          {error && <div className="bg-red-100 text-red-600 p-3 rounded-lg mb-4 text-sm">{error}</div>}
          <div className="space-y-4">
            <input
              type="text"
              value={totpCode}
              onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
              placeholder="000000"
              maxLength={6}
              className="w-full p-4 border border-twitter-gray-lighter rounded-lg focus:outline-none focus:border-twitter-blue text-center text-3xl font-bold tracking-widest font-mono"
            />
            <button
              onClick={verify2FALogin}
              disabled={loading || totpCode.length !== 6}
              className="w-full bg-twitter-blue hover:bg-twitter-blue-dark text-white py-3 rounded-full font-semibold transition-colors disabled:opacity-50"
            >
              {loading ? 'Verifying...' : 'Verify Code'}
            </button>
          </div>
          <div className="mt-4 text-center">
            <button onClick={() => { setRequiresTotpCode(false); setTempToken(null); setTotpCode(''); setError(null) }} className="text-twitter-blue text-sm hover:underline">
              Back to Login
            </button>
          </div>
        </div>
      </div>
    )
  }

  if (!token) {
    return (
      <div className="min-h-screen bg-twitter-gray-lightest flex items-center justify-center p-4">
        <div className="bg-white rounded-2xl p-8 w-full max-w-md shadow-lg">
          <div className="text-center mb-6">
            <div className="flex items-center justify-center gap-3 mb-2">
              <img src={logoSvg} alt="AgentPay" className="w-10 h-10" />
              <h1 className="text-3xl font-semibold text-twitter-blue tracking-tight" style={{ fontFamily: 'system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif' }}>AgentPay</h1>
            </div>
            <p className="text-twitter-gray">Venmo for AI Agents</p>
          </div>
          
          <div className="flex gap-2 mb-6">
            <button
              onClick={() => setAuthMode('login')}
              className={`flex-1 py-2 rounded-full font-semibold transition-colors ${
                authMode === 'login' 
                  ? 'bg-twitter-blue text-white' 
                  : 'bg-twitter-gray-lightest text-twitter-gray'
              }`}
            >
              Login
            </button>
            <button
              onClick={() => setAuthMode('register')}
              className={`flex-1 py-2 rounded-full font-semibold transition-colors ${
                authMode === 'register' 
                  ? 'bg-twitter-blue text-white' 
                  : 'bg-twitter-gray-lightest text-twitter-gray'
              }`}
            >
              Register
            </button>
          </div>
          
          {error && (
            <div className="bg-red-100 text-red-600 p-3 rounded-lg mb-4 text-sm">
              {error}
            </div>
          )}
          
          {authMode === 'login' ? (
            <form onSubmit={handleLogin} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-twitter-gray mb-1">Email</label>
                <input
                  type="email"
                  value={loginEmail}
                  onChange={(e) => setLoginEmail(e.target.value)}
                  className="w-full p-3 border border-twitter-gray-lighter rounded-lg focus:outline-none focus:border-twitter-blue"
                  placeholder="you@example.com"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-twitter-gray mb-1">Password</label>
                <input
                  type="password"
                  value={loginPassword}
                  onChange={(e) => setLoginPassword(e.target.value)}
                  className="w-full p-3 border border-twitter-gray-lighter rounded-lg focus:outline-none focus:border-twitter-blue"
                  placeholder="••••••••"
                  required
                />
              </div>
              <button
                type="submit"
                disabled={loading}
                className="w-full bg-twitter-blue hover:bg-twitter-blue-dark text-white py-3 rounded-full font-semibold transition-colors disabled:opacity-50"
              >
                {loading ? 'Logging in...' : 'Login'}
              </button>
            </form>
          ) : (
            <form onSubmit={handleRegister} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-twitter-gray mb-1">Display Name</label>
                <input
                  type="text"
                  value={registerName}
                  onChange={(e) => setRegisterName(e.target.value)}
                  className="w-full p-3 border border-twitter-gray-lighter rounded-lg focus:outline-none focus:border-twitter-blue"
                  placeholder="Your name"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-twitter-gray mb-1">Email</label>
                <input
                  type="email"
                  value={registerEmail}
                  onChange={(e) => setRegisterEmail(e.target.value)}
                  className="w-full p-3 border border-twitter-gray-lighter rounded-lg focus:outline-none focus:border-twitter-blue"
                  placeholder="you@example.com"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-twitter-gray mb-1">Password</label>
                <input
                  type="password"
                  value={registerPassword}
                  onChange={(e) => setRegisterPassword(e.target.value)}
                  className="w-full p-3 border border-twitter-gray-lighter rounded-lg focus:outline-none focus:border-twitter-blue"
                  placeholder="••••••••"
                  required
                />
              </div>
              <button
                type="submit"
                disabled={loading}
                className="w-full bg-twitter-blue hover:bg-twitter-blue-dark text-white py-3 rounded-full font-semibold transition-colors disabled:opacity-50"
              >
                {loading ? 'Creating account...' : 'Create Account'}
              </button>
            </form>
          )}
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-white">
      {/* Header */}
      <header className="bg-twitter-blue text-white p-4 shadow-md">
        <div className="max-w-md mx-auto flex items-center justify-between">
          <div className="flex items-center gap-2">
            <img src={logoSvg} alt="AgentPay" className="w-8 h-8" />
            <h1 className="text-xl font-semibold tracking-tight" style={{ fontFamily: 'system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif' }}>AgentPay</h1>
          </div>
          <div className="flex items-center gap-3">
            <div className="text-sm opacity-90">@{user?.displayName || 'User'}</div>
            <button 
              onClick={handleLogout}
              className="text-xs px-3 py-1 border border-white/50 rounded-full hover:bg-white/20 transition-colors"
            >
              Logout
            </button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-md mx-auto pb-20">
        {activeTab === 'home' && (
          <div className="p-4">
            {/* Balance Card */}
            <div className="bg-twitter-blue rounded-2xl p-6 text-white mb-6 shadow-lg">
              <div className="text-sm opacity-90 mb-1">Your Balance</div>
              <div className="flex items-baseline gap-3 mb-2">
                <div className="text-4xl font-bold">
                  {wallet ? formatBalance(wallet.usdcBalance) : '$0.00'}
                </div>
                <div className="text-lg opacity-80">
                  {wallet ? `${wallet.solBalance.toFixed(4)} SOL` : '0.0000 SOL'}
                </div>
              </div>
              <div className="text-xs opacity-75 font-mono">
                {wallet ? wallet.publicKey.slice(0, 6) + '...' + wallet.publicKey.slice(-4) : 'No wallet'}
              </div>
            </div>

            {/* Action Buttons */}
            <div className="grid grid-cols-2 gap-4 mb-6">
              <button 
                onClick={() => setShowSendModal(true)}
                className="bg-twitter-blue hover:bg-twitter-blue-dark text-white py-3 px-6 rounded-full font-semibold transition-colors"
              >
                Send
              </button>
              <button
                onClick={() => setShowRequestModal(true)}
                className="bg-twitter-blue hover:bg-twitter-blue-dark text-white py-3 px-6 rounded-full font-semibold transition-colors"
              >
                Request
              </button>
            </div>

            <div className="grid grid-cols-2 gap-4 mb-6">
              <button
                onClick={() => setShowDepositModal(true)}
                className="border-2 border-twitter-blue text-twitter-blue hover:bg-twitter-blue-light py-3 px-6 rounded-full font-semibold transition-colors"
              >
                Deposit
              </button>
              <button
                onClick={() => setShowWithdrawModal(true)}
                className="border-2 border-twitter-blue text-twitter-blue hover:bg-twitter-blue-light py-3 px-6 rounded-full font-semibold transition-colors"
              >
                Withdraw
              </button>
            </div>

            {/* Incoming Payment Requests */}
            {incomingRequests.length > 0 && (
              <div className="bg-white rounded-xl border-2 border-yellow-400 mb-6">
                <div className="p-4 border-b border-yellow-200 bg-yellow-50 rounded-t-xl">
                  <h2 className="font-bold text-yellow-800">Payment Requests ({incomingRequests.length})</h2>
                </div>
                <div className="divide-y divide-yellow-100">
                  {incomingRequests.map(req => (
                    <div key={req.id} className="p-4">
                      <div className="flex items-center justify-between mb-2">
                        <div>
                          <div className="font-semibold text-twitter-black">
                            @{req.requestedBy.displayName} requested {formatBalance(req.amount)}
                          </div>
                          {req.memo && <div className="text-sm text-twitter-gray">{req.memo}</div>}
                          <div className="text-xs text-twitter-gray mt-1">{formatTime(req.createdAt)}</div>
                        </div>
                        <div className="font-bold text-yellow-600">{formatBalance(req.amount)}</div>
                      </div>
                      <div className="flex gap-2">
                        <button
                          onClick={() => handleAcceptPaymentRequest(req.id)}
                          disabled={loading}
                          className="flex-1 bg-green-500 hover:bg-green-600 text-white py-2 rounded-full text-sm font-semibold transition-colors disabled:opacity-50"
                        >
                          Accept
                        </button>
                        <button
                          onClick={() => handleDismissPaymentRequest(req.id)}
                          disabled={loading}
                          className="flex-1 bg-gray-200 hover:bg-gray-300 text-gray-700 py-2 rounded-full text-sm font-semibold transition-colors disabled:opacity-50"
                        >
                          Dismiss
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Transaction History */}
            <div className="bg-white rounded-xl border border-twitter-gray-lighter">
              <div className="p-4 border-b border-twitter-gray-lighter flex justify-between items-center">
                <h2 className="font-bold text-twitter-black">Recent Activity</h2>
                <button
                  onClick={async () => {
                    setRefreshing(true)
                    await Promise.all([fetchWallet(), fetchTransactions(), fetchIncomingRequests()])
                    setRefreshing(false)
                  }}
                  disabled={refreshing}
                  className="flex items-center gap-1.5 text-twitter-blue text-sm hover:underline disabled:opacity-50"
                >
                  {refreshing && (
                    <svg className="animate-spin h-3.5 w-3.5" viewBox="0 0 24 24" fill="none">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                    </svg>
                  )}
                  Refresh
                </button>
              </div>
              <div className="divide-y divide-twitter-gray-lighter">
                {transactions.length === 0 ? (
                  <div className="p-8 text-center text-twitter-gray">
                    <div className="text-4xl mb-2">📭</div>
                    <p>No transactions yet</p>
                    <p className="text-sm mt-1">Send or receive money to get started</p>
                  </div>
                ) : (
                  transactions.map(tx => {
                    const badge = getStatusBadge(tx)
                    const isPending = isRequest(tx) && tx.status === 'PENDING'
                    const isDismissed = isRequest(tx) && tx.status === 'CANCELLED'
                    return (
                      <div key={tx.id} className={`p-4 flex items-center justify-between hover:bg-twitter-gray-lightest transition-colors ${isDismissed ? 'opacity-50' : ''}`}>
                        <div className="flex items-center gap-3">
                          <div className={`w-10 h-10 rounded-full flex items-center justify-center text-white font-bold ${getTransactionColor(tx)}`}>
                            {getTransactionIcon(tx)}
                          </div>
                          <div>
                            <div className="font-semibold text-twitter-black flex items-center gap-2">
                              {getTransactionLabel(tx)}
                              {badge && <span className={`text-xs px-2 py-0.5 rounded-full ${badge.color}`}>{badge.text}</span>}
                            </div>
                            <div className="text-sm text-twitter-gray">{formatTime(tx.createdAt)}</div>
                            {tx.memo && <div className="text-xs text-twitter-gray-light">{tx.memo}</div>}
                          </div>
                        </div>
                        <div className={`font-bold ${isPending || isDismissed ? 'text-gray-400' : isPositive(tx) ? 'text-green-600' : 'text-twitter-black'}`}>
                          {isPending || isDismissed ? '' : isPositive(tx) ? '+' : '-'}{formatBalance(tx.amount)}
                        </div>
                      </div>
                    )
                  })
                )}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'friends' && (
          <div className="p-4 space-y-4">
            {/* Toast notification */}
            {toast && (
              <div className="fixed top-6 left-1/2 -translate-x-1/2 z-50 bg-twitter-blue text-white px-6 py-3 rounded-full shadow-lg text-sm font-semibold animate-fade-in">
                {toast}
              </div>
            )}
            {/* Search Section */}
            <div className="bg-white rounded-xl border border-twitter-gray-lighter overflow-hidden">
              <div className="p-4 border-b border-twitter-gray-lighter">
                <h2 className="font-bold text-twitter-black">Find Friends</h2>
              </div>
              <div className="p-4">
                <div className="relative">
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Search by name..."
                    className="w-full p-3 pl-10 border border-twitter-gray-lighter rounded-lg focus:outline-none focus:border-twitter-blue"
                  />
                  <svg className="w-5 h-5 text-twitter-gray absolute left-3 top-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                  </svg>
                </div>
                
                {/* Search Results */}
                {isSearching && (
                  <div className="mt-3 text-center text-twitter-gray text-sm">Searching...</div>
                )}
                
                {searchResults.length > 0 && (
                  <div className="mt-3 divide-y divide-twitter-gray-lighter">
                    {searchResults.map(result => (
                      <div key={result.id} className="py-3 flex items-center justify-between">
                        <div>
                          <div className="font-semibold text-twitter-black">@{result.displayName}</div>
                          <div className="text-xs text-twitter-gray">
                            {result.type} {result.walletAddress && `• ${result.walletAddress.slice(0, 4)}...${result.walletAddress.slice(-4)}`}
                          </div>
                        </div>
                        {pendingSentIds.has(result.id) ? (
                          <span className="px-4 py-1.5 text-twitter-gray text-sm border border-twitter-gray-lighter rounded-full">
                            Requested
                          </span>
                        ) : (
                          <button
                            onClick={() => handleAddFriend(result.id)}
                            disabled={loading}
                            className="px-4 py-1.5 bg-twitter-blue text-white text-sm rounded-full hover:bg-twitter-blue-dark transition-colors disabled:opacity-50"
                          >
                            Add
                          </button>
                        )}
                      </div>
                    ))}
                  </div>
                )}
                
                {searchQuery.trim() && !isSearching && searchResults.length === 0 && (
                  <div className="mt-3 text-center text-twitter-gray text-sm">No users found</div>
                )}
              </div>
            </div>

            {/* Friend Requests Inbox */}
            {friendRequests.length > 0 && (
              <div className="bg-white rounded-xl border border-yellow-300 overflow-hidden">
                <div className="p-4 border-b border-yellow-200 bg-yellow-50 flex justify-between items-center">
                  <h2 className="font-bold text-twitter-black">Friend Requests</h2>
                  <span className="text-sm bg-twitter-blue text-white px-2 py-0.5 rounded-full">{friendRequests.length}</span>
                </div>
                <div className="divide-y divide-twitter-gray-lighter">
                  {friendRequests.map(req => (
                    <div key={req.id} className="p-4 flex items-center justify-between">
                      <div>
                        <div className="font-semibold text-twitter-black">@{req.from.displayName}</div>
                        <div className="text-xs text-twitter-gray">
                          <span className={`px-2 py-0.5 rounded-full ${req.from.type === 'HUMAN' ? 'bg-blue-100 text-blue-600' : 'bg-purple-100 text-purple-600'}`}>
                            {req.from.type}
                          </span>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => handleAcceptRequest(req.id)}
                          className="px-4 py-1.5 bg-twitter-blue text-white text-sm rounded-full hover:bg-twitter-blue-dark transition-colors"
                        >
                          Accept
                        </button>
                        <button
                          onClick={() => handleDeclineRequest(req.id)}
                          className="px-3 py-1.5 text-red-400 text-sm hover:text-red-600 transition-colors"
                        >
                          Decline
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Friends List */}
            <div className="bg-white rounded-xl border border-twitter-gray-lighter overflow-hidden">
              <div className="p-4 border-b border-twitter-gray-lighter flex justify-between items-center">
                <h2 className="font-bold text-twitter-black">My Friends</h2>
                <span className="text-sm text-twitter-gray">{friends.length}</span>
              </div>
              
              {friends.length === 0 ? (
                <div className="p-8 text-center text-twitter-gray">
                  <FriendsIcon className="w-12 h-12 mx-auto mb-3 opacity-50" />
                  <p>No friends yet</p>
                  <p className="text-sm mt-1">Search above to add friends</p>
                </div>
              ) : (
                <div className="divide-y divide-twitter-gray-lighter">
                  {friends.map(friend => (
                    <div key={friend.id} className="p-4 flex items-center justify-between hover:bg-twitter-gray-lightest transition-colors">
                      <div 
                        className="flex-1 cursor-pointer"
                        onClick={() => {
                          setSendRecipient(friend.id)
                          setSendRecipientName(friend.displayName)
                          setActiveTab('home')
                          setShowSendModal(true)
                        }}
                      >
                        <div className="font-semibold text-twitter-black">@{friend.displayName}</div>
                        <div className="flex items-center gap-2 text-xs text-twitter-gray">
                          <span className={`px-2 py-0.5 rounded-full ${friend.type === 'HUMAN' ? 'bg-blue-100 text-blue-600' : 'bg-purple-100 text-purple-600'}`}>
                            {friend.type}
                          </span>
                          {friend.walletAddress && (
                            <span>{friend.walletAddress.slice(0, 4)}...{friend.walletAddress.slice(-4)}</span>
                          )}
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => {
                            setSendRecipient(friend.id)
                            setSendRecipientName(friend.displayName)
                            setShowSendModal(true)
                          }}
                          className="px-3 py-1.5 text-twitter-blue text-sm hover:bg-twitter-blue-light rounded-full transition-colors"
                        >
                          Send
                        </button>
                        <button
                          onClick={() => handleRemoveFriend(friend.id)}
                          className="px-3 py-1.5 text-red-400 text-sm hover:text-red-600 transition-colors"
                        >
                          Remove
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'settings' && (
          <div className="p-4 space-y-4">
            {(error || settingsSuccess) && (
              <div className={`p-3 rounded-lg text-sm ${settingsSuccess ? 'bg-green-100 text-green-600' : 'bg-red-100 text-red-600'}`}>
                {settingsSuccess || error}
              </div>
            )}

            <form onSubmit={handleUpdateSettings} className="bg-white rounded-xl border border-twitter-gray-lighter overflow-hidden">
              <div className="p-4 border-b border-twitter-gray-lighter">
                <h2 className="font-bold text-twitter-black">Profile</h2>
              </div>
              <div className="p-4 space-y-3">
                <div>
                  <label className="block text-sm font-medium text-twitter-gray mb-1">Username</label>
                  <div className="relative">
                    <span className="absolute left-3 top-3 text-twitter-gray font-semibold">@</span>
                    <input
                      type="text"
                      value={editDisplayName}
                      onChange={(e) => setEditDisplayName(e.target.value.replace(/^@/, '').replace(/\s/g, ''))}
                      placeholder={user?.displayName || 'username'}
                      className="w-full p-3 pl-8 border border-twitter-gray-lighter rounded-lg focus:outline-none focus:border-twitter-blue"
                    />
                  </div>
                  <p className="text-xs text-twitter-gray mt-1">Must be unique. This is how others find you.</p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-twitter-gray mb-1">Daily Limit (USDC)</label>
                  <input
                    type="number"
                    value={editDailyLimit}
                    onChange={(e) => setEditDailyLimit(e.target.value)}
                    placeholder="No limit"
                    step="1"
                    min="0"
                    className="w-full p-3 border border-twitter-gray-lighter rounded-lg focus:outline-none focus:border-twitter-blue"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-twitter-gray mb-1">Per-Transaction Limit (USDC)</label>
                  <input
                    type="number"
                    value={editTxLimit}
                    onChange={(e) => setEditTxLimit(e.target.value)}
                    placeholder="No limit"
                    step="1"
                    min="0"
                    className="w-full p-3 border border-twitter-gray-lighter rounded-lg focus:outline-none focus:border-twitter-blue"
                  />
                </div>
                <button
                  type="submit"
                  disabled={loading}
                  className="w-full bg-twitter-blue hover:bg-twitter-blue-dark text-white py-3 rounded-full font-semibold transition-colors disabled:opacity-50"
                >
                  {loading ? 'Saving...' : 'Save Settings'}
                </button>
              </div>
            </form>

            <div className="bg-white rounded-xl border border-twitter-gray-lighter overflow-hidden">
              <div className="p-4 border-b border-twitter-gray-lighter flex justify-between items-center">
                <h2 className="font-bold text-twitter-black">Connected Banks</h2>
                <button
                  onClick={() => setShowBankModal(true)}
                  className="text-twitter-blue text-sm font-semibold hover:underline"
                >
                  + Add
                </button>
              </div>
              {bankAccounts.length === 0 ? (
                <div className="p-6 text-center text-twitter-gray">
                  <p className="text-sm">No bank accounts connected</p>
                  <p className="text-xs mt-1">Connect a bank for deposits & withdrawals</p>
                </div>
              ) : (
                <div className="divide-y divide-twitter-gray-lighter">
                  {bankAccounts.map(bank => (
                    <div key={bank.id} className="p-4 flex items-center justify-between">
                      <div>
                        <div className="font-semibold text-twitter-black">
                          {bank.bankName} {bank.isDefault && <span className="text-xs text-twitter-blue ml-1">(Default)</span>}
                        </div>
                        <div className="text-sm text-twitter-gray">
                          {bank.accountType === 'CHECKING' ? 'Checking' : 'Savings'} ****{bank.accountLast4}
                        </div>
                      </div>
                      <button
                        onClick={() => handleRemoveBank(bank.id)}
                        className="text-red-400 text-xs hover:text-red-600"
                      >
                        Remove
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="bg-white rounded-xl border border-twitter-gray-lighter overflow-hidden">
              <div className="p-4 border-b border-twitter-gray-lighter">
                <h2 className="font-bold text-twitter-black">Wallet</h2>
              </div>
              <div className="p-4">
                <div className="text-sm text-twitter-gray mb-1">Your Solana Address</div>
                <div className="font-mono text-xs bg-twitter-gray-lightest p-3 rounded-lg break-all">
                  {wallet?.publicKey || 'No wallet'}
                </div>
              </div>
            </div>

            <button
              onClick={handleLogout}
              className="w-full border-2 border-red-400 text-red-500 hover:bg-red-50 py-3 rounded-full font-semibold transition-colors"
            >
              Log Out
            </button>
          </div>
        )}
      </main>

      {/* Bottom Navigation */}
      <nav className="fixed bottom-0 left-0 right-0 bg-white border-t border-twitter-gray-lighter">
        <div className="max-w-md mx-auto flex justify-around">
          <button 
            onClick={() => setActiveTab('home')}
            className={`flex-1 py-3 text-center ${activeTab === 'home' ? 'text-twitter-blue' : 'text-twitter-gray'}`}
          >
            <HomeIcon className="w-6 h-6 mx-auto" />
            <div className="text-xs mt-1">Home</div>
          </button>
          <button 
            onClick={() => setActiveTab('friends')}
            className={`flex-1 py-3 text-center ${activeTab === 'friends' ? 'text-twitter-blue' : 'text-twitter-gray'}`}
          >
            <FriendsIcon className="w-6 h-6 mx-auto" />
            <div className="text-xs mt-1">Friends</div>
          </button>
          <button 
            onClick={() => setActiveTab('settings')}
            className={`flex-1 py-3 text-center ${activeTab === 'settings' ? 'text-twitter-blue' : 'text-twitter-gray'}`}
          >
            <SettingsIcon className="w-6 h-6 mx-auto" />
            <div className="text-xs mt-1">Settings</div>
          </button>
        </div>
      </nav>

      {/* Send Modal */}
      {showSendModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-2xl p-6 w-full max-w-sm">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-xl font-bold">Send Money</h3>
              <button 
                onClick={() => setShowSendModal(false)}
                className="text-twitter-gray hover:text-twitter-black"
              >
                ✕
              </button>
            </div>
            
            {error && (
              <div className="bg-red-100 text-red-600 p-3 rounded-lg mb-4 text-sm">
                {error}
              </div>
            )}
            
            <form onSubmit={handleSend} className="space-y-4">
              <div className="relative">
                <label className="block text-sm font-medium text-twitter-gray mb-1">To</label>
                {sendRecipient ? (
                  <div className="flex items-center gap-2 p-3 border border-twitter-blue bg-twitter-blue/5 rounded-lg">
                    <span className="font-semibold text-twitter-blue">@{sendRecipientName}</span>
                    <button type="button" onClick={() => { setSendRecipient(''); setSendRecipientName(''); setSendSearch('') }} className="ml-auto text-twitter-gray hover:text-red-500 text-sm">Clear</button>
                  </div>
                ) : (
                  <input
                    type="text"
                    value={sendSearch}
                    onChange={(e) => setSendSearch(e.target.value)}
                    placeholder="@username"
                    className="w-full p-3 border border-twitter-gray-lighter rounded-lg focus:outline-none focus:border-twitter-blue"
                  />
                )}
                {sendSearchResults.length > 0 && !sendRecipient && (
                  <div className="absolute left-0 right-0 mt-1 bg-white border border-twitter-gray-lighter rounded-lg shadow-lg z-10 max-h-48 overflow-y-auto">
                    {sendSearchResults.map(u => (
                      <button
                        key={u.id}
                        type="button"
                        onClick={() => { setSendRecipient(u.id); setSendRecipientName(u.displayName); setSendSearchResults([]) }}
                        className="w-full text-left px-4 py-3 hover:bg-twitter-gray-lightest flex items-center justify-between"
                      >
                        <span className="font-semibold">@{u.displayName}</span>
                        <span className={`text-xs px-2 py-0.5 rounded-full ${u.type === 'HUMAN' ? 'bg-blue-100 text-blue-600' : 'bg-purple-100 text-purple-600'}`}>{u.type}</span>
                      </button>
                    ))}
                  </div>
                )}
              </div>
              <div>
                <label className="block text-sm font-medium text-twitter-gray mb-1">Amount (USDC)</label>
                <input 
                  type="number" 
                  value={sendAmount}
                  onChange={(e) => setSendAmount(e.target.value)}
                  placeholder="0.00"
                  step="0.01"
                  min="0.01"
                  className="w-full p-3 border border-twitter-gray-lighter rounded-lg focus:outline-none focus:border-twitter-blue"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-twitter-gray mb-1">Note (optional)</label>
                <input 
                  type="text" 
                  value={sendMemo}
                  onChange={(e) => setSendMemo(e.target.value)}
                  placeholder="What's this for?"
                  className="w-full p-3 border border-twitter-gray-lighter rounded-lg focus:outline-none focus:border-twitter-blue"
                />
              </div>
              <button 
                type="submit"
                disabled={loading}
                className="w-full bg-twitter-blue hover:bg-twitter-blue-dark text-white py-3 rounded-full font-semibold transition-colors disabled:opacity-50"
              >
                {loading ? 'Sending...' : 'Send'}
              </button>
            </form>
          </div>
        </div>
      )}
      {/* Request Modal */}
      {showRequestModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-2xl p-6 w-full max-w-sm">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-xl font-bold">Request Money</h3>
              <button onClick={() => { setShowRequestModal(false); setError(null) }} className="text-twitter-gray hover:text-twitter-black">&#10005;</button>
            </div>
            {error && <div className="bg-red-100 text-red-600 p-3 rounded-lg mb-4 text-sm">{error}</div>}
            <form onSubmit={handleRequest} className="space-y-4">
              <div className="relative">
                <label className="block text-sm font-medium text-twitter-gray mb-1">From</label>
                {requestRecipient ? (
                  <div className="flex items-center gap-2 p-3 border border-twitter-blue bg-twitter-blue/5 rounded-lg">
                    <span className="font-semibold text-twitter-blue">@{requestRecipientName}</span>
                    <button type="button" onClick={() => { setRequestRecipient(''); setRequestRecipientName(''); setRequestSearch('') }} className="ml-auto text-twitter-gray hover:text-red-500 text-sm">Clear</button>
                  </div>
                ) : (
                  <input
                    type="text"
                    value={requestSearch}
                    onChange={(e) => setRequestSearch(e.target.value)}
                    placeholder="@username"
                    className="w-full p-3 border border-twitter-gray-lighter rounded-lg focus:outline-none focus:border-twitter-blue"
                  />
                )}
                {requestSearchResults.length > 0 && !requestRecipient && (
                  <div className="absolute left-0 right-0 mt-1 bg-white border border-twitter-gray-lighter rounded-lg shadow-lg z-10 max-h-48 overflow-y-auto">
                    {requestSearchResults.map(u => (
                      <button
                        key={u.id}
                        type="button"
                        onClick={() => { setRequestRecipient(u.id); setRequestRecipientName(u.displayName); setRequestSearchResults([]) }}
                        className="w-full text-left px-4 py-3 hover:bg-twitter-gray-lightest flex items-center justify-between"
                      >
                        <span className="font-semibold">@{u.displayName}</span>
                        <span className={`text-xs px-2 py-0.5 rounded-full ${u.type === 'HUMAN' ? 'bg-blue-100 text-blue-600' : 'bg-purple-100 text-purple-600'}`}>{u.type}</span>
                      </button>
                    ))}
                  </div>
                )}
              </div>
              <div>
                <label className="block text-sm font-medium text-twitter-gray mb-1">Amount (USDC)</label>
                <input type="number" value={requestAmount} onChange={(e) => setRequestAmount(e.target.value)} placeholder="0.00" step="0.01" min="0.01" className="w-full p-3 border border-twitter-gray-lighter rounded-lg focus:outline-none focus:border-twitter-blue" required />
              </div>
              <div>
                <label className="block text-sm font-medium text-twitter-gray mb-1">Note (optional)</label>
                <input type="text" value={requestMemo} onChange={(e) => setRequestMemo(e.target.value)} placeholder="What's this for?" className="w-full p-3 border border-twitter-gray-lighter rounded-lg focus:outline-none focus:border-twitter-blue" />
              </div>
              <button type="submit" disabled={loading} className="w-full bg-twitter-blue hover:bg-twitter-blue-dark text-white py-3 rounded-full font-semibold transition-colors disabled:opacity-50">
                {loading ? 'Requesting...' : 'Request'}
              </button>
            </form>
          </div>
        </div>
      )}

      {/* Deposit Modal */}
      {showDepositModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-2xl p-6 w-full max-w-sm">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-xl font-bold">Add Funds</h3>
              <button onClick={() => { setShowDepositModal(false); setError(null) }} className="text-twitter-gray hover:text-twitter-black">&#10005;</button>
            </div>
            {error && <div className="bg-red-100 text-red-600 p-3 rounded-lg mb-4 text-sm">{error}</div>}
            <form onSubmit={handleDeposit} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-twitter-gray mb-1">Amount (USDC)</label>
                <input type="number" value={depositAmount} onChange={(e) => setDepositAmount(e.target.value)} placeholder="10" step="1" min="1" max="10000" className="w-full p-3 border border-twitter-gray-lighter rounded-lg focus:outline-none focus:border-twitter-blue" required />
              </div>
              <div className="flex gap-2">
                {[10, 50, 100, 500].map(amt => (
                  <button key={amt} type="button" onClick={() => setDepositAmount(String(amt))} className={`flex-1 py-2 rounded-full text-sm font-semibold transition-colors ${depositAmount === String(amt) ? 'bg-twitter-blue text-white' : 'bg-twitter-gray-lightest text-twitter-gray hover:bg-twitter-gray-lighter'}`}>
                    ${amt}
                  </button>
                ))}
              </div>
              <button type="submit" disabled={loading} className="w-full bg-twitter-blue hover:bg-twitter-blue-dark text-white py-3 rounded-full font-semibold transition-colors disabled:opacity-50">
                {loading ? 'Depositing...' : `Deposit $${depositAmount || '10'}`}
              </button>
              {bankAccounts.length > 0 ? (
                <p className="text-xs text-twitter-gray text-center">From {bankAccounts.find(b => b.isDefault)?.bankName || bankAccounts[0].bankName} ****{bankAccounts.find(b => b.isDefault)?.accountLast4 || bankAccounts[0].accountLast4}</p>
              ) : (
                <p className="text-xs text-twitter-gray text-center">Demo mode: Test funds added instantly</p>
              )}
            </form>
          </div>
        </div>
      )}

      {/* Connect Bank Modal */}
      {showBankModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-2xl p-6 w-full max-w-sm">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-xl font-bold">Connect Bank Account</h3>
              <button onClick={() => { setShowBankModal(false); setError(null) }} className="text-twitter-gray hover:text-twitter-black">&#10005;</button>
            </div>
            {error && <div className="bg-red-100 text-red-600 p-3 rounded-lg mb-4 text-sm">{error}</div>}
            <form onSubmit={handleConnectBank} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-twitter-gray mb-1">Bank Name</label>
                <input type="text" value={bankName} onChange={(e) => setBankName(e.target.value)} placeholder="e.g. Chase, Bank of America" className="w-full p-3 border border-twitter-gray-lighter rounded-lg focus:outline-none focus:border-twitter-blue" required />
              </div>
              <div>
                <label className="block text-sm font-medium text-twitter-gray mb-1">Account Type</label>
                <div className="flex gap-2">
                  <button type="button" onClick={() => setBankAccountType('CHECKING')} className={`flex-1 py-2 rounded-full text-sm font-semibold transition-colors ${bankAccountType === 'CHECKING' ? 'bg-twitter-blue text-white' : 'bg-twitter-gray-lightest text-twitter-gray'}`}>Checking</button>
                  <button type="button" onClick={() => setBankAccountType('SAVINGS')} className={`flex-1 py-2 rounded-full text-sm font-semibold transition-colors ${bankAccountType === 'SAVINGS' ? 'bg-twitter-blue text-white' : 'bg-twitter-gray-lightest text-twitter-gray'}`}>Savings</button>
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium text-twitter-gray mb-1">Account Number</label>
                <input type="password" value={bankAccountNumber} onChange={(e) => setBankAccountNumber(e.target.value.replace(/\D/g, '').slice(0, 17))} placeholder="Enter full account number" maxLength={17} className="w-full p-3 border border-twitter-gray-lighter rounded-lg focus:outline-none focus:border-twitter-blue font-mono" required />
                <p className="text-xs text-twitter-gray mt-1">Encrypted at rest. Only last 4 digits are ever displayed.</p>
              </div>
              <div>
                <label className="block text-sm font-medium text-twitter-gray mb-1">Routing Number</label>
                <input type="password" value={bankRoutingNumber} onChange={(e) => setBankRoutingNumber(e.target.value.replace(/\D/g, '').slice(0, 9))} placeholder="9-digit routing number" maxLength={9} className="w-full p-3 border border-twitter-gray-lighter rounded-lg focus:outline-none focus:border-twitter-blue font-mono" required />
                <p className="text-xs text-twitter-gray mt-1">Encrypted at rest. Only last 4 digits are ever displayed.</p>
              </div>
              <button type="submit" disabled={loading} className="w-full bg-twitter-blue hover:bg-twitter-blue-dark text-white py-3 rounded-full font-semibold transition-colors disabled:opacity-50">
                {loading ? 'Connecting...' : 'Connect Bank'}
              </button>
            </form>
          </div>
        </div>
      )}

      {/* Withdraw Modal */}
      {showWithdrawModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-2xl p-6 w-full max-w-sm">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-xl font-bold">Withdraw</h3>
              <button onClick={() => { setShowWithdrawModal(false); setError(null) }} className="text-twitter-gray hover:text-twitter-black">&#10005;</button>
            </div>
            {error && <div className="bg-red-100 text-red-600 p-3 rounded-lg mb-4 text-sm">{error}</div>}
            <form onSubmit={handleWithdraw} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-twitter-gray mb-1">To Wallet Address</label>
                <input type="text" value={withdrawAddress} onChange={(e) => setWithdrawAddress(e.target.value)} placeholder="Solana wallet address" className="w-full p-3 border border-twitter-gray-lighter rounded-lg focus:outline-none focus:border-twitter-blue" required />
              </div>
              <div>
                <label className="block text-sm font-medium text-twitter-gray mb-1">Amount (USDC)</label>
                <input type="number" value={withdrawAmount} onChange={(e) => setWithdrawAmount(e.target.value)} placeholder="0.00" step="0.01" min="0.01" className="w-full p-3 border border-twitter-gray-lighter rounded-lg focus:outline-none focus:border-twitter-blue" required />
              </div>
              <div>
                <label className="block text-sm font-medium text-twitter-gray mb-1">Note (optional)</label>
                <input type="text" value={withdrawMemo} onChange={(e) => setWithdrawMemo(e.target.value)} placeholder="What's this for?" className="w-full p-3 border border-twitter-gray-lighter rounded-lg focus:outline-none focus:border-twitter-blue" />
              </div>
              <button type="submit" disabled={loading} className="w-full bg-twitter-blue hover:bg-twitter-blue-dark text-white py-3 rounded-full font-semibold transition-colors disabled:opacity-50">
                {loading ? 'Withdrawing...' : 'Withdraw'}
              </button>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}

export default App
