import { useState } from 'react'
import { Shield, History, BarChart2, BookOpen } from 'lucide-react'
import { ScanView } from './views/ScanView'
import { HistoryView } from './views/HistoryView'
import { StatsView } from './views/StatsView'
import { AboutView } from './views/AboutView'

type Tab = 'scan' | 'history' | 'stats' | 'about'

const TABS: { id: Tab; label: string; Icon: typeof Shield }[] = [
  { id: 'scan',    label: 'Inspect', Icon: Shield },
  { id: 'history', label: 'History', Icon: History },
  { id: 'stats',   label: 'Metrics', Icon: BarChart2 },
  { id: 'about',   label: 'About',   Icon: BookOpen },
]

export default function App() {
  const [tab, setTab] = useState<Tab>('scan')

  return (
    <div className="min-h-screen bg-gray-950 flex flex-col">
      {/* Top nav */}
      <header className="border-b border-gray-800 bg-gray-900/80 backdrop-blur sticky top-0 z-10">
        <div className="max-w-5xl mx-auto px-4 sm:px-6 flex items-center gap-6 h-14">
          <div className="flex items-center gap-2 shrink-0">
            <Shield size={20} className="text-indigo-400" />
            <span className="font-bold text-gray-100 text-sm tracking-tight">goggles-ai</span>
          </div>
          <div className="hidden text-xs uppercase tracking-[0.2em] text-gray-500 md:block">
            Secure the content your agent reads
          </div>
          <nav className="flex gap-1 overflow-x-auto">
            {TABS.map(({ id, label, Icon }) => (
              <button
                key={id}
                onClick={() => setTab(id)}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm font-medium whitespace-nowrap transition-colors ${
                  tab === id
                    ? 'bg-indigo-600 text-white'
                    : 'text-gray-400 hover:text-gray-200 hover:bg-gray-700'
                }`}
              >
                <Icon size={14} />
                {label}
              </button>
            ))}
          </nav>
        </div>
      </header>

      {/* Content */}
      <main className="flex-1 max-w-5xl mx-auto w-full px-4 sm:px-6 py-8">
        {tab === 'scan'    && <ScanView />}
        {tab === 'history' && <HistoryView />}
        {tab === 'stats'   && <StatsView />}
        {tab === 'about'   && <AboutView />}
      </main>
    </div>
  )
}
