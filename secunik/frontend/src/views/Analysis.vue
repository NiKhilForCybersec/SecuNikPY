<!-- src/views/Analysis.vue -->
<template>
  <div class="space-y-6">
    <!-- Page Header -->
    <div class="bg-white rounded-lg shadow-sm p-6">
      <div class="flex items-center justify-between">
        <div>
          <h1 class="text-2xl font-bold text-gray-900">Analysis Results</h1>
          <p class="text-gray-600 mt-1">
            View and manage file analysis results
          </p>
        </div>
        <div class="flex items-center space-x-3">
          <button
            @click="refreshFiles"
            :disabled="loading"
            class="btn btn-secondary btn-sm"
          >
            <svg v-if="!loading" class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
            <div v-else class="spinner w-4 h-4 mr-2"></div>
            Refresh
          </button>
        </div>
      </div>
    </div>

    <!-- Filters -->
    <div class="card">
      <div class="card-body">
        <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">Search Files</label>
            <input
              v-model="searchTerm"
              type="text"
              placeholder="Search by filename or case..."
              class="form-input"
            />
          </div>
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">Filter by Status</label>
            <select v-model="statusFilter" class="form-select">
              <option value="">All Statuses</option>
              <option value="uploaded">Uploaded</option>
              <option value="analyzing">Analyzing</option>
              <option value="completed">Completed</option>
              <option value="failed">Failed</option>
            </select>
          </div>
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">Filter by Type</label>
            <select v-model="typeFilter" class="form-select">
              <option value="">All Types</option>
              <option value="application/pdf">PDF</option>
              <option value="text/plain">Text</option>
              <option value="application/zip">Archive</option>
              <option value="application/json">JSON</option>
            </select>
          </div>
          <div class="flex items-end">
            <button
              @click="clearFilters"
              class="btn btn-secondary w-full"
            >
              Clear Filters
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- Files Table -->
    <div class="card">
      <div class="card-header">
        <div class="flex items-center justify-between">
          <h2 class="text-lg font-semibold text-gray-900">
            Files ({{ filteredFiles.length }})
          </h2>
          <div v-if="selectedFiles.length > 0" class="flex items-center space-x-2">
            <span class="text-sm text-gray-600">
              {{ selectedFiles.length }} selected
            </span>
            <button
              @click="bulkAnalyze"
              class="btn btn-primary btn-sm"
            >
              Analyze Selected
            </button>
          </div>
        </div>
      </div>
      <div class="card-body p-0">
        <div v-if="loading" class="text-center py-8">
          <div class="spinner w-8 h-8 mx-auto mb-4"></div>
          <p class="text-gray-600">Loading files...</p>
        </div>
        
        <div v-else-if="filteredFiles.length === 0" class="text-center py-8">
          <svg class="w-12 h-12 text-gray-400 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
          </svg>
          <h3 class="text-lg font-medium text-gray-900 mb-2">No files found</h3>
          <p class="text-gray-600 mb-4">
            No files match your current filters.
          </p>
          <router-link to="/upload" class="btn btn-primary">
            Upload Files
          </router-link>
        </div>
        
        <div v-else class="overflow-x-auto">
          <table class="table">
            <thead class="table-header">
              <tr>
                <th class="w-12">
                  <input
                    type="checkbox"
                    class="form-checkbox"
                    :checked="allSelected"
                    @change="toggleSelectAll"
                  />
                </th>
                <th>File Name</th>
                <th>Case ID</th>
                <th>Type</th>
                <th>Size</th>
                <th>Upload Time</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody class="table-body">
              <tr 
                v-for="file in filteredFiles" 
                :key="file.file_id"
                class="table-row-hover"
              >
                <td>
                  <input
                    type="checkbox"
                    class="form-checkbox"
                    :checked="selectedFiles.includes(file.file_id)"
                    @change="toggleFileSelection(file.file_id)"
                  />
                </td>
                <td>
                  <div class="flex items-center">
                    <div>
                      <div class="text-sm font-medium text-gray-900">
                        {{ file.filename }}
                      </div>
                      <div class="text-sm text-gray-500">
                        ID: {{ file.file_id }}
                      </div>
                    </div>
                  </div>
                </td>
                <td class="text-sm text-gray-600">{{ file.case_id }}</td>
                <td class="text-sm text-gray-600">{{ getFileTypeDisplay(file.file_type) }}</td>
                <td class="text-sm text-gray-600">{{ formatFileSize(file.file_size) }}</td>
                <td class="text-sm text-gray-600">{{ formatTime(file.upload_timestamp) }}</td>
                <td>
                  <span 
                    class="badge"
                    :class="getStatusBadgeClass(file.status)"
                  >
                    {{ file.status }}
                  </span>
                </td>
                <td>
                  <div class="flex items-center space-x-2">
                    <button
                      v-if="file.status === 'uploaded'"
                      @click="analyzeFile(file.file_id)"
                      class="btn btn-primary btn-sm"
                    >
                      Analyze
                    </button>
                    <button
                      v-if="file.status === 'completed'"
                      @click="viewResults(file.file_id)"
                      class="btn btn-secondary btn-sm"
                    >
                      View Results
                    </button>
                    <button
                      @click="downloadFile(file.file_id)"
                      class="btn btn-secondary btn-sm"
                      title="Download file"
                    >
                      <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                      </svg>
                    </button>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import { ref, computed, onMounted, watch } from 'vue'
import { useRouter } from 'vue-router'
import { useFilesStore } from '@/store/files'
import { useUIStore } from '@/store/ui'
import { formatDistanceToNow } from 'date-fns'

export default {
  name: 'Analysis',
  setup() {
    const router = useRouter()
    const filesStore = useFilesStore()
    const uiStore = useUIStore()
    
    // Reactive data
    const loading = ref(false)
    const searchTerm = ref('')
    const statusFilter = ref('')
    const typeFilter = ref('')
    const selectedFiles = ref([])
    
    // Computed properties
    const filteredFiles = computed(() => {
      let files = filesStore.files
      
      if (searchTerm.value) {
        const term = searchTerm.value.toLowerCase()
        files = files.filter(f => 
          f.filename.toLowerCase().includes(term) ||
          f.case_id.toLowerCase().includes(term)
        )
      }
      
      if (statusFilter.value) {
        files = files.filter(f => f.status === statusFilter.value)
      }
      
      if (typeFilter.value) {
        files = files.filter(f => f.file_type === typeFilter.value)
      }
      
      return files
    })
    
    const allSelected = computed(() => {
      return filteredFiles.value.length > 0 && 
             filteredFiles.value.every(f => selectedFiles.value.includes(f.file_id))
    })
    
    // Methods
    async function refreshFiles() {
      loading.value = true
      try {
        await filesStore.loadFiles()
      } catch (error) {
        uiStore.showNotification({
          type: 'error',
          title: 'Load Failed',
          message: 'Failed to load files'
        })
      } finally {
        loading.value = false
      }
    }
    
    function clearFilters() {
      searchTerm.value = ''
      statusFilter.value = ''
      typeFilter.value = ''
    }
    
    function toggleFileSelection(fileId) {
      const index = selectedFiles.value.indexOf(fileId)
      if (index > -1) {
        selectedFiles.value.splice(index, 1)
      } else {
        selectedFiles.value.push(fileId)
      }
    }
    
    function toggleSelectAll() {
      if (allSelected.value) {
        selectedFiles.value = []
      } else {
        selectedFiles.value = filteredFiles.value.map(f => f.file_id)
      }
    }
    
    async function analyzeFile(fileId) {
      try {
        await filesStore.analyzeFile(fileId)
        uiStore.showNotification({
          type: 'success',
          title: 'Analysis Started',
          message: 'File analysis has been started'
        })
      } catch (error) {
        uiStore.showNotification({
          type: 'error',
          title: 'Analysis Failed',
          message: 'Failed to start file analysis'
        })
      }
    }
    
    async function bulkAnalyze() {
      if (selectedFiles.value.length === 0) return
      
      try {
        for (const fileId of selectedFiles.value) {
          await filesStore.analyzeFile(fileId)
        }
        
        uiStore.showNotification({
          type: 'success',
          title: 'Bulk Analysis Started',
          message: `Started analysis for ${selectedFiles.value.length} files`
        })
        
        selectedFiles.value = []
      } catch (error) {
        uiStore.showNotification({
          type: 'error',
          title: 'Bulk Analysis Failed',
          message: 'Failed to start bulk analysis'
        })
      }
    }
    
    function viewResults(fileId) {
      router.push(`/analysis/${fileId}`)
    }
    
    function downloadFile(fileId) {
      // Placeholder for file download functionality
      uiStore.showNotification({
        type: 'info',
        title: 'Download',
        message: 'File download functionality will be available in Phase 6'
      })
    }
    
    function formatFileSize(bytes) {
      if (bytes === 0) return '0 B'
      const k = 1024
      const sizes = ['B', 'KB', 'MB', 'GB']
      const i = Math.floor(Math.log(bytes) / Math.log(k))
      return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
    }
    
    function formatTime(timestamp) {
      try {
        return formatDistanceToNow(new Date(timestamp), { addSuffix: true })
      } catch {
        return 'Unknown'
      }
    }
    
    function getStatusBadgeClass(status) {
      const classes = {
        uploaded: 'badge-secondary',
        analyzing: 'badge-warning',
        completed: 'badge-success',
        failed: 'badge-danger'
      }
      return classes[status] || 'badge-secondary'
    }
    
    function getFileTypeDisplay(mimeType) {
      const typeMap = {
        'application/pdf': 'PDF',
        'text/plain': 'Text',
        'application/json': 'JSON',
        'text/csv': 'CSV',
        'application/zip': 'ZIP',
        'application/x-dosexec': 'Executable'
      }
      return typeMap[mimeType] || 'Unknown'
    }
    
    // Watch for filter changes to clear selection
    watch([searchTerm, statusFilter, typeFilter], () => {
      selectedFiles.value = []
    })
    
    // Initialize
    onMounted(() => {
      refreshFiles()
    })
    
    return {
      loading,
      searchTerm,
      statusFilter,
      typeFilter,
      selectedFiles,
      filteredFiles,
      allSelected,
      refreshFiles,
      clearFilters,
      toggleFileSelection,
      toggleSelectAll,
      analyzeFile,
      bulkAnalyze,
      viewResults,
      downloadFile,
      formatFileSize,
      formatTime,
      getStatusBadgeClass,
      getFileTypeDisplay
    }
  }
}
</script>

<!-- src/views/Cases.vue -->
<template>
  <div class="space-y-6">
    <!-- Page Header -->
    <div class="bg-white rounded-lg shadow-sm p-6">
      <div class="flex items-center justify-between">
        <div>
          <h1 class="text-2xl font-bold text-gray-900">Case Management</h1>
          <p class="text-gray-600 mt-1">
            Organize and manage your investigation cases
          </p>
        </div>
        <div class="flex items-center space-x-3">
          <button
            @click="refreshCases"
            :disabled="loading"
            class="btn btn-secondary btn-sm"
          >
            <svg v-if="!loading" class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
            <div v-else class="spinner w-4 h-4 mr-2"></div>
            Refresh
          </button>
          <button
            @click="showCreateModal = true"
            class="btn btn-primary btn-sm"
          >
            <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
            </svg>
            New Case
          </button>
        </div>
      </div>
    </div>

    <!-- Cases Grid -->
    <div v-if="loading" class="text-center py-8">
      <div class="spinner w-8 h-8 mx-auto mb-4"></div>
      <p class="text-gray-600">Loading cases...</p>
    </div>
    
    <div v-else-if="cases.length === 0" class="text-center py-12">
      <svg class="w-16 h-16 text-gray-400 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2H5a2 2 0 00-2-2z" />
      </svg>
      <h3 class="text-xl font-medium text-gray-900 mb-2">No cases found</h3>
      <p class="text-gray-600 mb-6">
        Create your first case to start organizing evidence files.
      </p>
      <button
        @click="showCreateModal = true"
        class="btn btn-primary"
      >
        Create Your First Case
      </button>
    </div>
    
    <div v-else class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
      <div 
        v-for="case_ in cases" 
        :key="case_.case_id"
        class="card hover:shadow-lg transition-shadow duration-200 cursor-pointer"
        @click="viewCase(case_.case_id)"
      >
        <div class="card-body">
          <div class="flex items-start justify-between mb-4">
            <div>
              <h3 class="text-lg font-semibold text-gray-900">{{ case_.name }}</h3>
              <p class="text-sm text-gray-600">{{ case_.case_id }}</p>
            </div>
            <span 
              class="badge"
              :class="getStatusBadgeClass(case_.status)"
            >
              {{ case_.status }}
            </span>
          </div>
          
          <p v-if="case_.description" class="text-gray-600 text-sm mb-4">
            {{ case_.description }}
          </p>
          
          <div class="space-y-2 text-sm text-gray-600">
            <div class="flex justify-between">
              <span>Created:</span>
              <span>{{ formatTime(case_.created_timestamp) }}</span>
            </div>
            <div class="flex justify-between">
              <span>Files:</span>
              <span>{{ case_.file_count || 0 }}</span>
            </div>
          </div>
        </div>
        
        <div class="card-footer">
          <div class="flex justify-between items-center">
            <button
              @click.stop="viewCase(case_.case_id)"
              class="text-blue-600 hover:text-blue-800 text-sm font-medium"
            >
              View Details →
            </button>
            <div class="flex space-x-2">
              <button
                @click.stop="editCase(case_)"
                class="text-gray-600 hover:text-gray-800"
                title="Edit case"
              >
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                </svg>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Create Case Modal -->
    <div v-if="showCreateModal" class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div class="bg-white rounded-lg p-6 max-w-md w-full mx-4">
        <h3 class="text-lg font-semibold text-gray-900 mb-4">Create New Case</h3>
        
        <form @submit.prevent="createCase">
          <div class="space-y-4">
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-2">
                Case Name *
              </label>
              <input
                v-model="newCase.name"
                type="text"
                class="form-input"
                placeholder="Enter case name..."
                required
              />
            </div>
            
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-2">
                Description
              </label>
              <textarea
                v-model="newCase.description"
                class="form-textarea"
                rows="3"
                placeholder="Enter case description..."
              ></textarea>
            </div>
          </div>
          
          <div class="flex justify-end space-x-3 mt-6">
            <button
              type="button"
              @click="cancelCreate"
              class="btn btn-secondary"
            >
              Cancel
            </button>
            <button
              type="submit"
              :disabled="!newCase.name.trim() || creating"
              class="btn btn-primary"
            >
              <div v-if="creating" class="spinner w-4 h-4 mr-2"></div>
              Create Case
            </button>
          </div>
        </form>
      </div>
    </div>
  </div>
</template>

<script>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useUIStore } from '@/store/ui'
import { formatDistanceToNow } from 'date-fns'
import api from '@/services/api'

export default {
  name: 'Cases',
  setup() {
    const router = useRouter()
    const uiStore = useUIStore()
    
    // Reactive data
    const loading = ref(false)
    const cases = ref([])
    const showCreateModal = ref(false)
    const creating = ref(false)
    const newCase = ref({
      name: '',
      description: ''
    })
    
    // Methods
    async function loadCases() {
      loading.value = true
      try {
        const response = await api.cases.list()
        cases.value = response.cases || []
      } catch (error) {
        console.error('Failed to load cases:', error)
        uiStore.showNotification({
          type: 'error',
          title: 'Load Failed',
          message: 'Failed to load cases'
        })
      } finally {
        loading.value = false
      }
    }
    
    async function refreshCases() {
      await loadCases()
    }
    
    async function createCase() {
      if (!newCase.value.name.trim()) return
      
      creating.value = true
      try {
        const response = await api.cases.create(
          newCase.value.name.trim(),
          newCase.value.description.trim()
        )
        
        // Add new case to list
        const createdCase = {
          case_id: response.case_id,
          name: response.name || newCase.value.name.trim(),
          description: newCase.value.description.trim(),
          status: response.status || 'active',
          created_timestamp: new Date().toISOString(),
          file_count: 0
        }
        
        cases.value.unshift(createdCase)
        
        uiStore.showNotification({
          type: 'success',
          title: 'Case Created',
          message: `Case "${createdCase.name}" created successfully`
        })
        
        // Reset form and close modal
        newCase.value = { name: '', description: '' }
        showCreateModal.value = false
        
      } catch (error) {
        console.error('Failed to create case:', error)
        uiStore.showNotification({
          type: 'error',
          title: 'Creation Failed',
          message: 'Failed to create case'
        })
      } finally {
        creating.value = false
      }
    }
    
    function cancelCreate() {
      newCase.value = { name: '', description: '' }
      showCreateModal.value = false
    }
    
    function viewCase(caseId) {
      router.push(`/cases/${caseId}`)
    }
    
    function editCase(case_) {
      // Placeholder for edit functionality
      uiStore.showNotification({
        type: 'info',
        title: 'Edit Case',
        message: 'Case editing functionality will be available in Phase 5'
      })
    }
    
    function formatTime(timestamp) {
      try {
        return formatDistanceToNow(new Date(timestamp), { addSuffix: true })
      } catch {
        return 'Unknown'
      }
    }
    
    function getStatusBadgeClass(status) {
      const classes = {
        active: 'badge-success',
        closed: 'badge-secondary',
        archived: 'badge-warning'
      }
      return classes[status] || 'badge-secondary'
    }
    
    // Initialize
    onMounted(() => {
      loadCases()
    })
    
    return {
      loading,
      cases,
      showCreateModal,
      creating,
      newCase,
      loadCases,
      refreshCases,
      createCase,
      cancelCreate,
      viewCase,
      editCase,
      formatTime,
      getStatusBadgeClass
    }
  }
}
</script>

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