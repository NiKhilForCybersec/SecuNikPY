<!-- src/components/upload/FileUploader.vue -->
<template>
  <div class="space-y-6">
    <!-- Upload Area -->
    <div class="card">
      <div class="card-body">
        <div
          ref="dropZone"
          class="upload-zone"
          :class="{ 'dragover': isDragOver }"
          @click="triggerFileInput"
          @dragover.prevent="handleDragOver"
          @dragleave.prevent="handleDragLeave"
          @drop.prevent="handleDrop"
        >
          <div class="text-center">
            <svg 
              class="w-16 h-16 text-gray-400 mx-auto mb-4"
              :class="isDragOver ? 'text-blue-500' : ''"
              fill="none" 
              stroke="currentColor" 
              viewBox="0 0 24 24"
            >
              <path 
                stroke-linecap="round" 
                stroke-linejoin="round" 
                stroke-width="2" 
                d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" 
              />
            </svg>
            
            <div v-if="!isDragOver">
              <h3 class="text-xl font-medium text-gray-900 mb-2">
                Drop files here to upload
              </h3>
              <p class="text-gray-600 mb-4">
                Or click to browse and select files from your computer
              </p>
              <button class="btn btn-primary">
                Choose Files
              </button>
            </div>
            
            <div v-else>
              <h3 class="text-xl font-medium text-blue-600 mb-2">
                Release to upload files
              </h3>
              <p class="text-blue-500">
                Drop your files here
              </p>
            </div>
          </div>
        </div>
        
        <!-- Hidden File Input -->
        <input
          ref="fileInput"
          type="file"
          multiple
          class="hidden"
          accept=".pdf,.doc,.docx,.txt,.zip,.rar,.7z,.log,.evtx,.json,.csv,.xml,.pcap,.pcapng,.mem,.dmp,.img,.dd,.pst,.ost,.eml,.exe,.dll"
          @change="handleFileSelect"
        />
        
        <!-- File Limits Info -->
        <div class="mt-4 p-4 bg-blue-50 rounded-lg">
          <div class="flex items-start">
            <svg class="w-5 h-5 text-blue-500 mt-0.5 mr-3 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
              <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
            </svg>
            <div class="text-sm text-blue-700">
              <p class="font-medium mb-1">File Upload Guidelines:</p>
              <ul class="space-y-1">
                <li>• Maximum file size: 100 MB per file</li>
                <li>• Supported formats: PDF, Word, Archives, Logs, Network captures, Memory dumps, Email files</li>
                <li>• You can upload multiple files at once</li>
                <li>• Files will be automatically analyzed after upload</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Case Selection -->
    <div class="card">
      <div class="card-header">
        <h2 class="text-lg font-semibold text-gray-900">Case Assignment</h2>
        <p class="text-sm text-gray-600 mt-1">
          Assign uploaded files to a case for organization
        </p>
      </div>
      <div class="card-body">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <!-- Existing Case Selection -->
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">
              Select Existing Case
            </label>
            <select 
              v-model="selectedCaseId"
              class="form-select"
              @change="handleCaseSelection"
            >
              <option value="">Select a case...</option>
              <option 
                v-for="case_ in availableCases" 
                :key="case_.case_id" 
                :value="case_.case_id"
              >
                {{ case_.name }} ({{ case_.case_id }})
              </option>
            </select>
          </div>
          
          <!-- New Case Creation -->
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">
              Or Create New Case
            </label>
            <div class="flex space-x-2">
              <input
                v-model="newCaseName"
                type="text"
                placeholder="Enter case name..."
                class="form-input flex-1"
                @keyup.enter="createNewCase"
              />
              <button
                @click="createNewCase"
                :disabled="!newCaseName.trim() || creatingCase"
                class="btn btn-secondary"
              >
                <div v-if="creatingCase" class="spinner w-4 h-4 mr-2"></div>
                Create
              </button>
            </div>
          </div>
        </div>
        
        <!-- Selected Case Display -->
        <div v-if="currentCase" class="mt-4 p-3 bg-green-50 rounded-lg border border-green-200">
          <div class="flex items-center">
            <svg class="w-5 h-5 text-green-500 mr-2" fill="currentColor" viewBox="0 0 20 20">
              <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd" />
            </svg>
            <span class="text-sm font-medium text-green-800">
              Files will be uploaded to case: {{ currentCase.name }}
            </span>
          </div>
        </div>
      </div>
    </div>

    <!-- Upload Queue -->
    <div v-if="uploadQueue.length > 0" class="card">
      <div class="card-header">
        <div class="flex items-center justify-between">
          <h2 class="text-lg font-semibold text-gray-900">Upload Queue</h2>
          <div class="flex space-x-2">
            <button
              @click="startUpload"
              :disabled="isUploading"
              class="btn btn-primary btn-sm"
            >
              <div v-if="isUploading" class="spinner w-4 h-4 mr-2"></div>
              {{ isUploading ? 'Uploading...' : 'Start Upload' }}
            </button>
            <button
              @click="clearQueue"
              :disabled="isUploading"
              class="btn btn-secondary btn-sm"
            >
              Clear Queue
            </button>
          </div>
        </div>
      </div>
      <div class="card-body">
        <div class="space-y-3">
          <div 
            v-for="(file, index) in uploadQueue" 
            :key="file.id"
            class="flex items-center justify-between p-3 bg-gray-50 rounded-lg"
          >
            <div class="flex items-center space-x-3">
              <div class="w-8 h-8 bg-blue-100 rounded-lg flex items-center justify-center">
                <svg class="w-4 h-4 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
              </div>
              <div>
                <p class="font-medium text-gray-900">{{ file.name }}</p>
                <p class="text-sm text-gray-600">
                  {{ formatFileSize(file.size) }} • {{ getFileType(file.name) }}
                </p>
              </div>
            </div>
            <div class="flex items-center space-x-2">
              <span class="text-sm text-gray-600">{{ index + 1 }} of {{ uploadQueue.length }}</span>
              <button
                @click="removeFromQueue(index)"
                :disabled="isUploading"
                class="text-red-600 hover:text-red-800 p-1"
              >
                <svg class="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
                  <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd" />
                </svg>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import { ref, computed, onMounted } from 'vue'
import { useUploadStore } from '@/store/upload'
import { useUIStore } from '@/store/ui'
import api from '@/services/api'

export default {
  name: 'FileUploader',
  emits: ['uploaded'],
  setup(props, { emit }) {
    const uploadStore = useUploadStore()
    const uiStore = useUIStore()
    
    // Refs
    const dropZone = ref(null)
    const fileInput = ref(null)
    const isDragOver = ref(false)
    const uploadQueue = ref([])
    const selectedCaseId = ref('')
    const newCaseName = ref('')
    const availableCases = ref([])
    const creatingCase = ref(false)
    
    // Computed
    const isUploading = computed(() => uploadStore.isUploading)
    const currentCase = computed(() => {
      if (!selectedCaseId.value) return null
      return availableCases.value.find(c => c.case_id === selectedCaseId.value)
    })
    
    // Methods
    function triggerFileInput() {
      fileInput.value?.click()
    }
    
    function handleDragOver(e) {
      e.preventDefault()
      isDragOver.value = true
    }
    
    function handleDragLeave(e) {
      e.preventDefault()
      isDragOver.value = false
    }
    
    function handleDrop(e) {
      e.preventDefault()
      isDragOver.value = false
      
      const files = Array.from(e.dataTransfer.files)
      addFilesToQueue(files)
    }
    
    function handleFileSelect(e) {
      const files = Array.from(e.target.files)
      addFilesToQueue(files)
      
      // Clear the input so the same file can be selected again
      e.target.value = ''
    }
    
    function addFilesToQueue(files) {
      const validFiles = files.filter(file => {
        // Check file size (100MB limit)
        if (file.size > 100 * 1024 * 1024) {
          uiStore.showNotification({
            type: 'error',
            title: 'File Too Large',
            message: `File "${file.name}" is larger than 100MB limit`
          })
          return false
        }
        
        // Check if file is already in queue
        if (uploadQueue.value.some(f => f.name === file.name && f.size === file.size)) {
          uiStore.showNotification({
            type: 'warning',
            title: 'Duplicate File',
            message: `File "${file.name}" is already in the upload queue`
          })
          return false
        }
        
        return true
      })
      
      // Add unique ID to each file
      const filesWithId = validFiles.map(file => ({
        ...file,
        id: Date.now() + Math.random()
      }))
      
      uploadQueue.value.push(...filesWithId)
      
      if (validFiles.length > 0) {
        uiStore.showNotification({
          type: 'success',
          title: 'Files Added',
          message: `${validFiles.length} file(s) added to upload queue`
        })
      }
    }
    
    function removeFromQueue(index) {
      uploadQueue.value.splice(index, 1)
    }
    
    function clearQueue() {
      uploadQueue.value = []
    }
    
    async function startUpload() {
      if (uploadQueue.value.length === 0) {
        uiStore.showNotification({
          type: 'warning',
          title: 'No Files',
          message: 'Please add files to upload queue first'
        })
        return
      }
      
      try {
        const files = [...uploadQueue.value]
        clearQueue()
        
        // Upload files sequentially
        for (const file of files) {
          try {
            const result = await uploadStore.uploadFile(file, selectedCaseId.value)
            emit('uploaded', result)
          } catch (error) {
            console.error('Failed to upload file:', file.name, error)
          }
        }
        
      } catch (error) {
        console.error('Upload failed:', error)
      }
    }
    
    async function loadCases() {
      try {
        const response = await api.cases.list()
        availableCases.value = response.cases || []
      } catch (error) {
        console.error('Failed to load cases:', error)
      }
    }
    
    async function createNewCase() {
      if (!newCaseName.value.trim()) return
      
      creatingCase.value = true
      try {
        const response = await api.cases.create(newCaseName.value.trim())
        
        // Add to available cases
        const newCase = {
          case_id: response.case_id,
          name: response.name || newCaseName.value.trim(),
          status: response.status || 'active'
        }
        availableCases.value.unshift(newCase)
        
        // Select the new case
        selectedCaseId.value = response.case_id
        newCaseName.value = ''
        
        uiStore.showNotification({
          type: 'success',
          title: 'Case Created',
          message: `New case "${newCase.name}" created successfully`
        })
        
      } catch (error) {
        console.error('Failed to create case:', error)
        uiStore.showNotification({
          type: 'error',
          title: 'Creation Failed',
          message: 'Failed to create new case'
        })
      } finally {
        creatingCase.value = false
      }
    }
    
    function handleCaseSelection() {
      if (selectedCaseId.value) {
        const selectedCase = currentCase.value
        if (selectedCase) {
          uiStore.showNotification({
            type: 'info',
            title: 'Case Selected',
            message: `Files will be uploaded to "${selectedCase.name}"`
          })
        }
      }
    }
    
    function formatFileSize(bytes) {
      if (bytes === 0) return '0 B'
      const k = 1024
      const sizes = ['B', 'KB', 'MB', 'GB']
      const i = Math.floor(Math.log(bytes) / Math.log(k))
      return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
    }
    
    function getFileType(filename) {
      const extension = filename.split('.').pop()?.toLowerCase()
      const typeMap = {
        pdf: 'PDF Document',
        doc: 'Word Document',
        docx: 'Word Document',
        txt: 'Text File',
        zip: 'ZIP Archive',
        rar: 'RAR Archive',
        '7z': '7-Zip Archive',
        log: 'Log File',
        evtx: 'Event Log',
        json: 'JSON Data',
        csv: 'CSV Data',
        xml: 'XML Data',
        pcap: 'Network Capture',
        pcapng: 'Network Capture',
        mem: 'Memory Dump',
        dmp: 'Memory Dump',
        img: 'Disk Image',
        dd: 'Disk Image',
        pst: 'Outlook Data',
        ost: 'Outlook Data',
        eml: 'Email Message',
        exe: 'Executable',
        dll: 'Library File'
      }
      return typeMap[extension] || 'Unknown'
    }
    
    // Initialize
    onMounted(() => {
      loadCases()
    })
    
    return {
      // Refs
      dropZone,
      fileInput,
      isDragOver,
      uploadQueue,
      selectedCaseId,
      newCaseName,
      availableCases,
      creatingCase,
      
      // Computed
      isUploading,
      currentCase,
      
      // Methods
      triggerFileInput,
      handleDragOver,
      handleDragLeave,
      handleDrop,
      handleFileSelect,
      removeFromQueue,
      clearQueue,
      startUpload,
      createNewCase,
      handleCaseSelection,
      formatFileSize,
      getFileType
    }
  }
}
</script>

<style scoped>
.upload-zone {
  cursor: pointer;
  transition: all 0.2s ease-in-out;
}

.upload-zone:hover {
  border-color: #3b82f6;
  background-color: #eff6ff;
}

.upload-zone.dragover {
  border-color: #3b82f6 !important;
  background-color: #dbeafe !important;
}
</style>