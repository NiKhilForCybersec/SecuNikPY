<!-- src/views/Settings.vue -->
<template>
  <div class="space-y-6">
    <!-- Page Header -->
    <div class="bg-white rounded-lg shadow-sm p-6">
      <div>
        <h1 class="text-2xl font-bold text-gray-900">Settings</h1>
        <p class="text-gray-600 mt-1">
          Configure SecuNik platform settings and preferences
        </p>
      </div>
    </div>

    <!-- Settings Sections -->
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
      <!-- Settings Menu -->
      <div class="lg:col-span-1">
        <div class="card">
          <div class="card-header">
            <h2 class="text-lg font-semibold text-gray-900">Settings Categories</h2>
          </div>
          <div class="card-body p-0">
            <nav class="space-y-1">
              <button
                v-for="section in settingSections"
                :key="section.id"
                @click="activeSection = section.id"
                class="w-full text-left px-4 py-3 text-sm font-medium transition-colors duration-200"
                :class="activeSection === section.id 
                  ? 'bg-blue-50 text-blue-700 border-r-2 border-blue-500' 
                  : 'text-gray-700 hover:bg-gray-50'"
              >
                <div class="flex items-center">
                  <component :is="section.icon" class="w-5 h-5 mr-3" />
                  {{ section.name }}
                </div>
              </button>
            </nav>
          </div>
        </div>
      </div>

      <!-- Settings Content -->
      <div class="lg:col-span-2">
        <!-- General Settings -->
        <div v-if="activeSection === 'general'" class="card">
          <div class="card-header">
            <h3 class="text-lg font-semibold text-gray-900">General Settings</h3>
          </div>
          <div class="card-body space-y-6">
            <div>
              <h4 class="text-sm font-medium text-gray-900 mb-3">Application Preferences</h4>
              <div class="space-y-4">
                <div class="flex items-center justify-between">
                  <div>
                    <label class="text-sm font-medium text-gray-700">Auto-refresh dashboard</label>
                    <p class="text-sm text-gray-500">Automatically refresh dashboard data every 30 seconds</p>
                  </div>
                  <input type="checkbox" class="form-checkbox" checked disabled />
                </div>
                
                <div class="flex items-center justify-between">
                  <div>
                    <label class="text-sm font-medium text-gray-700">Show file type icons</label>
                    <p class="text-sm text-gray-500">Display file type icons in file listings</p>
                  </div>
                  <input type="checkbox" class="form-checkbox" checked disabled />
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- System Status -->
        <div v-if="activeSection === 'system'" class="card">
          <div class="card-header">
            <h3 class="text-lg font-semibold text-gray-900">System Status</h3>
          </div>
          <div class="card-body space-y-6">
            <div>
              <h4 class="text-sm font-medium text-gray-900 mb-3">Backend Connection</h4>
              <div class="flex items-center space-x-3">
                <div 
                  class="w-3 h-3 rounded-full"
                  :class="isBackendHealthy ? 'bg-green-400' : 'bg-red-400'"
                ></div>
                <span class="text-sm">
                  {{ isBackendHealthy ? 'Connected and operational' : 'Connection error' }}
                </span>
              </div>
            </div>
            
            <div>
              <h4 class="text-sm font-medium text-gray-900 mb-3">System Information</h4>
              <div class="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span class="text-gray-600">Platform Version:</span>
                  <span class="ml-2 font-medium">1.0.0</span>
                </div>
                <div>
                  <span class="text-gray-600">Backend Status:</span>
                  <span class="ml-2 font-medium">{{ backendStatus }}</span>
                </div>
                <div>
                  <span class="text-gray-600">Total Cases:</span>
                  <span class="ml-2 font-medium">{{ stats.total_cases || 0 }}</span>
                </div>
                <div>
                  <span class="text-gray-600">Total Files:</span>
                  <span class="ml-2 font-medium">{{ stats.total_files || 0 }}</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- Security Settings -->
        <div v-if="activeSection === 'security'" class="card">
          <div class="card-header">
            <h3 class="text-lg font-semibold text-gray-900">Security Settings</h3>
          </div>
          <div class="card-body space-y-6">
            <div>
              <h4 class="text-sm font-medium text-gray-900 mb-3">File Security</h4>
              <div class="space-y-4">
                <div class="flex items-center justify-between">
                  <div>
                    <label class="text-sm font-medium text-gray-700">Enable file scanning</label>
                    <p class="text-sm text-gray-500">Scan uploaded files for potential threats</p>
                  </div>
                  <input type="checkbox" class="form-checkbox" checked disabled />
                </div>
                
                <div class="flex items-center justify-between">
                  <div>
                    <label class="text-sm font-medium text-gray-700">Quarantine suspicious files</label>
                    <p class="text-sm text-gray-500">Automatically quarantine files flagged as suspicious</p>
                  </div>
                  <input type="checkbox" class="form-checkbox" checked disabled />
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- About -->
        <div v-if="activeSection === 'about'" class="card">
          <div class="card-header">
            <h3 class="text-lg font-semibold text-gray-900">About SecuNik</h3>
          </div>
          <div class="card-body space-y-6">
            <div class="text-center">
              <div class="text-6xl mb-4">🔐</div>
              <h4 class="text-xl font-semibold text-gray-900 mb-2">SecuNik</h4>
              <p class="text-gray-600 mb-4">Ultimate Local Cybersecurity Analysis Platform</p>
              <p class="text-sm text-gray-500">Version 1.0.0 - Phase 1</p>
            </div>
            
            <div class="border-t pt-6">
              <h5 class="text-sm font-medium text-gray-900 mb-3">Features</h5>
              <ul class="text-sm text-gray-600 space-y-2">
                <li>• File upload and basic analysis</li>
                <li>• Case management system</li>
                <li>• Multiple file format support</li>
                <li>• Local storage (no external dependencies)</li>
                <li>• Real-time dashboard updates</li>
              </ul>
            </div>
            
            <div class="border-t pt-6">
              <h5 class="text-sm font-medium text-gray-900 mb-3">Coming Soon</h5>
              <ul class="text-sm text-gray-600 space-y-2">
                <li>• AI-powered analysis (Phase 3)</li>
                <li>• Advanced forensic parsers (Phase 5)</li>
                <li>• Report generation (Phase 6)</li>
                <li>• Network visualization</li>
                <li>• Timeline analysis</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import { ref, computed, onMounted } from 'vue'
import { useAppStore } from '@/store/app'

export default {
  name: 'Settings',
  setup() {
    const appStore = useAppStore()
    
    const activeSection = ref('general')
    
    const settingSections = [
      { id: 'general', name: 'General', icon: 'div' },
      { id: 'system', name: 'System Status', icon: 'div' },
      { id: 'security', name: 'Security', icon: 'div' },
      { id: 'about', name: 'About', icon: 'div' }
    ]
    
    const isBackendHealthy = computed(() => appStore.isBackendHealthy)
    const backendStatus = computed(() => 
      appStore.backendHealth?.status || 'Unknown'
    )
    const stats = computed(() => appStore.systemStats)
    
    onMounted(() => {
      // Refresh system stats when settings page loads
      appStore.refreshSystemStats()
    })
    
    return {
      activeSection,
      settingSections,
      isBackendHealthy,
      backendStatus,
      stats
    }
  }
}
</script>