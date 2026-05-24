<script setup lang="ts">
import { ref, computed, onMounted, h } from 'vue'
import { invoke } from '@tauri-apps/api/core'
import { NButton, NTag, NSpace, useMessage } from 'naive-ui'
import type { AclEntry, AclTarget, EndpointTree } from '../types'
import type { DataTableColumns } from 'naive-ui'

const props = defineProps<{ nodeId: number }>()

const message = useMessage()
const loading = ref(false)
const saving = ref(false)
const error = ref<string | null>(null)
const entries = ref<AclEntry[]>([])
const dirty = ref(false)

// Device structure for cluster/endpoint dropdowns
const endpointTree = ref<EndpointTree | null>(null)

async function loadStructure() {
  try {
    endpointTree.value = await invoke<EndpointTree>('read_endpoint_structure', { nodeId: props.nodeId })
  } catch {
    // swallow - fall back to number inputs
  }
}

const endpointOptions = computed(() => {
  if (!endpointTree.value) return []
  return [
    { label: 'Any', value: null as number | null },
    ...endpointTree.value.endpoints.map(ep => ({
      label: `Endpoint ${ep.id}`,
      value: ep.id as number | null,
    })),
  ]
})

const clusterOptions = computed(() => {
  if (!endpointTree.value) return []
  const seen = new Map<number, string>()
  for (const ep of endpointTree.value.endpoints) {
    for (const cl of ep.clusters) {
      if (!seen.has(cl.id)) {
        seen.set(cl.id, cl.name)
      }
    }
  }
  return [
    { label: 'Any', value: null as number | null },
    ...Array.from(seen.entries())
      .sort((a, b) => a[0] - b[0])
      .map(([id, name]) => ({
        label: `${name} (0x${id.toString(16).padStart(4, '0').toUpperCase()})`,
        value: id as number | null,
      })),
  ]
})

const PRIVILEGE_LABELS: Record<number, string> = {
  1: 'View',
  2: 'ProxyView',
  3: 'Operate',
  4: 'Manage',
  5: 'Administer',
}

const AUTH_MODE_LABELS: Record<number, string> = {
  1: 'Pase',
  2: 'Case',
  3: 'Group',
}

const PRIVILEGE_OPTIONS = [
  { label: 'View (1)', value: 1 },
  { label: 'ProxyView (2)', value: 2 },
  { label: 'Operate (3)', value: 3 },
  { label: 'Manage (4)', value: 4 },
  { label: 'Administer (5)', value: 5 },
]

const AUTH_MODE_OPTIONS = [
  { label: 'Pase (1)', value: 1 },
  { label: 'Case (2)', value: 2 },
  { label: 'Group (3)', value: 3 },
]

function formatTarget(t: AclTarget): string {
  const parts: string[] = []
  if (t.endpoint !== null) parts.push(`EP:${t.endpoint}`)
  if (t.cluster !== null) parts.push(`CL:0x${t.cluster.toString(16).padStart(4, '0')}`)
  if (t.device_type !== null) parts.push(`DT:0x${t.device_type.toString(16).padStart(4, '0')}`)
  return parts.length > 0 ? parts.join(' ') : 'Any'
}

const columns: DataTableColumns<AclEntry> = [
  {
    title: 'Fabric',
    key: 'fabric_index',
    width: 60,
    render: (row) => row.fabric_index !== null ? String(row.fabric_index) : '-',
  },
  {
    title: 'Privilege',
    key: 'privilege',
    width: 110,
    render: (row) => {
      const label = row.privilege !== null ? (PRIVILEGE_LABELS[row.privilege] ?? String(row.privilege)) : '-'
      const type = row.privilege === 5 ? 'warning' : row.privilege === 4 ? 'info' : 'default'
      return h(NTag, { size: 'small', type, bordered: false }, { default: () => label })
    },
  },
  {
    title: 'Auth Mode',
    key: 'auth_mode',
    width: 90,
    render: (row) => row.auth_mode !== null ? (AUTH_MODE_LABELS[row.auth_mode] ?? String(row.auth_mode)) : '-',
  },
  {
    title: 'Subjects',
    key: 'subjects',
    render: (row) => {
      if (row.subjects.length === 0) return '-'
      const text = row.subjects.join(', ')
      return text.length > 60 ? text.slice(0, 57) + '...' : text
    },
  },
  {
    title: 'Targets',
    key: 'targets',
    render: (row) => {
      if (row.targets.length === 0) return 'Any'
      return row.targets.map(formatTarget).join('; ')
    },
  },
  {
    title: 'Actions',
    key: 'actions',
    width: 110,
    render: (_, idx) =>
      h(NSpace, { size: 'small' }, {
        default: () => [
          h(NButton, { size: 'tiny', onClick: () => openEdit(idx) }, { default: () => 'Edit' }),
          h(NButton, { size: 'tiny', type: 'error', ghost: true, onClick: () => deleteEntry(idx) }, { default: () => 'Delete' }),
        ],
      }),
  },
]

async function load() {
  loading.value = true
  error.value = null
  dirty.value = false
  try {
    entries.value = await invoke<AclEntry[]>('read_acl', { nodeId: props.nodeId })
  } catch (e: any) {
    error.value = e?.toString() ?? 'Unknown error'
  } finally {
    loading.value = false
  }
}

async function save() {
  saving.value = true
  error.value = null
  try {
    await invoke('write_acl', { nodeId: props.nodeId, entries: entries.value })
    dirty.value = false
    message.success('ACL saved')
    await load()
  } catch (e: any) {
    error.value = e?.toString() ?? 'Unknown error'
  } finally {
    saving.value = false
  }
}

function deleteEntry(idx: number) {
  entries.value.splice(idx, 1)
  dirty.value = true
}

// --- Entry modal ---

const showModal = ref(false)
const editIndex = ref<number | null>(null)
const formPrivilege = ref<number | null>(null)
const formAuthMode = ref<number | null>(null)
const formSubjects = ref<string[]>([])
const formTargets = ref<AclTarget[]>([])

const canConfirm = computed(() => {
  const hasPriv = formPrivilege.value !== null
  const hasAuth = formAuthMode.value !== null
  // At least one non-empty subject is required.
  // Targets are optional (empty = null = any target per Matter ACL spec).
  const hasSubject = formSubjects.value.some(s => s.trim() !== '')
  return hasPriv && hasAuth && hasSubject
})

function openAdd() {
  editIndex.value = null
  formPrivilege.value = 5
  formAuthMode.value = 2
  formSubjects.value = ['']
  formTargets.value = []   // empty = null = any target
  showModal.value = true
}

function openEdit(idx: number) {
  editIndex.value = idx
  const e = entries.value[idx]
  formPrivilege.value = e.privilege
  formAuthMode.value = e.auth_mode
  formSubjects.value = e.subjects.length > 0 ? [...e.subjects] : ['']
  // Only pre-populate targets that have at least one non-null field.
  // All-null target structs are invalid per the Matter spec; empty list
  // means "any target" (null wildcard), which is the correct default.
  formTargets.value = e.targets.filter(t =>
    t.cluster !== null || t.endpoint !== null || t.device_type !== null
  ).map(t => ({ ...t }))
  showModal.value = true
}

function addSubject() {
  formSubjects.value.push('')
}

function removeSubject(i: number) {
  if (formSubjects.value.length > 1) formSubjects.value.splice(i, 1)
}

function addTarget() {
  formTargets.value.push({ cluster: null, endpoint: null, device_type: null })
}

function removeTarget(i: number) {
  formTargets.value.splice(i, 1)
}

function confirmEntry() {
  if (!canConfirm.value) return
  const validSubjects = formSubjects.value.filter(s => s.trim() !== '')
  const fabricIndex = editIndex.value !== null ? entries.value[editIndex.value].fabric_index : null
  const entry: AclEntry = {
    privilege: formPrivilege.value,
    auth_mode: formAuthMode.value,
    subjects: validSubjects,
    targets: [...formTargets.value],
    fabric_index: fabricIndex,
  }
  if (editIndex.value !== null) {
    entries.value[editIndex.value] = entry
  } else {
    entries.value.push(entry)
  }
  dirty.value = true
  showModal.value = false
}

onMounted(() => {
  load()
  loadStructure()
})
defineExpose({ reload: load })
</script>

<template>
  <div>
    <div class="acl-toolbar">
      <n-button size="small" @click="openAdd" :disabled="loading || saving">
        + Add Entry
      </n-button>
      <n-button
        size="small"
        type="primary"
        :disabled="!dirty || saving"
        :loading="saving"
        @click="save"
      >
        Save Changes
      </n-button>
      <n-tag v-if="dirty" type="warning" size="small" :bordered="false">Unsaved changes</n-tag>
    </div>

    <n-spin v-if="loading" :show="true" style="margin-top: 24px" />
    <n-alert v-else-if="error" type="error" :title="error" style="margin-top: 12px" />
    <div v-else-if="entries.length === 0" class="hint">No ACL entries found.</div>
    <n-data-table
      v-else
      :columns="columns"
      :data="entries"
      size="small"
      :single-line="false"
    />

    <n-modal v-model:show="showModal" preset="dialog" :title="editIndex !== null ? 'Edit Entry' : 'Add Entry'" style="width: 640px">
      <n-form label-placement="left" label-width="100" size="small">
        <n-form-item label="Privilege">
          <n-select v-model:value="formPrivilege" :options="PRIVILEGE_OPTIONS" placeholder="Select privilege" />
        </n-form-item>
        <n-form-item label="Auth Mode">
          <n-select v-model:value="formAuthMode" :options="AUTH_MODE_OPTIONS" placeholder="Select auth mode" />
        </n-form-item>

        <n-form-item label="Subjects">
          <div class="subject-list">
            <div v-for="(_, i) in formSubjects" :key="i" class="subject-row">
              <n-input
                v-model:value="formSubjects[i]"
                placeholder="Node ID (decimal)"
                size="small"
                style="flex: 1"
              />
              <n-button
                size="tiny"
                type="error"
                ghost
                :disabled="formSubjects.length <= 1"
                @click="removeSubject(i)"
              >
                -
              </n-button>
            </div>
            <n-button size="tiny" @click="addSubject">+ Subject</n-button>
          </div>
        </n-form-item>

        <n-form-item label="Targets">
          <div class="target-list">
            <div v-if="formTargets.length === 0" class="target-hint">
              Empty = any target (null wildcard per Matter spec)
            </div>
            <div v-if="formTargets.length > 0" class="target-header">
              <span class="col-cluster">Cluster</span>
              <span class="col-endpoint">Endpoint</span>
              <span class="col-devtype">Device Type</span>
            </div>
            <div v-for="(_, i) in formTargets" :key="i" class="target-row">
              <!-- Cluster: select from device clusters when available, else number input -->
              <n-select
                v-if="clusterOptions.length > 0"
                v-model:value="formTargets[i].cluster"
                :options="clusterOptions"
                size="small"
                clearable
                filterable
                placeholder="Any cluster"
                class="col-cluster"
              />
              <n-input-number
                v-else
                v-model:value="formTargets[i].cluster"
                placeholder="Cluster ID"
                size="small"
                :min="0"
                :max="0xFFFFFFFF"
                class="col-cluster"
              />
              <!-- Endpoint: select from device endpoints when available, else number input -->
              <n-select
                v-if="endpointOptions.length > 0"
                v-model:value="formTargets[i].endpoint"
                :options="endpointOptions"
                size="small"
                clearable
                placeholder="Any endpoint"
                class="col-endpoint"
              />
              <n-input-number
                v-else
                v-model:value="formTargets[i].endpoint"
                placeholder="Endpoint"
                size="small"
                :min="0"
                :max="0xFFFF"
                class="col-endpoint"
              />
              <!-- Device type: number input (less common, no known-values list) -->
              <n-input-number
                v-model:value="formTargets[i].device_type"
                placeholder="Any"
                size="small"
                :min="0"
                :max="0xFFFFFFFF"
                class="col-devtype"
              />
              <n-button
                size="tiny"
                type="error"
                ghost
                @click="removeTarget(i)"
              >
                -
              </n-button>
            </div>
            <n-button size="tiny" @click="addTarget">+ Target</n-button>
          </div>
        </n-form-item>
      </n-form>
      <template #action>
        <n-space>
          <n-button size="small" @click="showModal = false">Cancel</n-button>
          <n-button size="small" type="primary" :disabled="!canConfirm" @click="confirmEntry">
            {{ editIndex !== null ? 'Update' : 'Add' }}
          </n-button>
        </n-space>
      </template>
    </n-modal>
  </div>
</template>

<style scoped>
.acl-toolbar {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 12px;
}
.hint {
  color: var(--n-text-color-disabled);
  padding: 20px;
  text-align: center;
}
.subject-list,
.target-list {
  display: flex;
  flex-direction: column;
  gap: 6px;
  width: 100%;
}
.subject-row {
  display: flex;
  align-items: center;
  gap: 6px;
}
.target-hint {
  font-size: 12px;
  color: var(--n-text-color-disabled);
  padding: 2px 0;
}
.target-header,
.target-row {
  display: grid;
  grid-template-columns: 1fr 130px 110px 28px;
  gap: 6px;
  align-items: center;
}
.target-header {
  font-size: 11px;
  color: var(--n-text-color-3);
  font-weight: 600;
  padding: 0 2px;
}
.col-cluster,
.col-endpoint,
.col-devtype {
  min-width: 0;
}
</style>
