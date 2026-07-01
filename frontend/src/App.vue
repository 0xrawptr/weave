<template>
  <a-layout class="app-shell">
    <a-layout-sider class="sidebar" width="232">
      <div class="brand">
        <div class="brand-mark">W</div>
        <div>
          <div class="brand-title">Weave</div>
          <div class="brand-subtitle">ASM 控制台</div>
        </div>
      </div>
      <a-menu v-model:selectedKeys="selectedKeys" theme="dark" mode="inline" class="nav-menu">
        <a-menu-item key="overview">
          <template #icon><DashboardOutlined /></template>
          总览
        </a-menu-item>
        <a-menu-item key="campaigns">
          <template #icon><FolderOpenOutlined /></template>
          活动
        </a-menu-item>
        <a-menu-item key="batches">
          <template #icon><PartitionOutlined /></template>
          批次
        </a-menu-item>
        <a-menu-item key="workItems">
          <template #icon><BarsOutlined /></template>
          工作项
        </a-menu-item>
        <a-menu-item key="assets">
          <template #icon><DatabaseOutlined /></template>
          资产
        </a-menu-item>
        <a-menu-item key="actions">
          <template #icon><ThunderboltOutlined /></template>
          动作
        </a-menu-item>
        <a-menu-item key="artifacts">
          <template #icon><ToolOutlined /></template>
          工件
        </a-menu-item>
        <a-menu-item key="policies">
          <template #icon><FileProtectOutlined /></template>
          策略
        </a-menu-item>
        <a-menu-item key="exports">
          <template #icon><DownloadOutlined /></template>
          导出
        </a-menu-item>
        <a-menu-item key="monitors">
          <template #icon><SyncOutlined /></template>
          监控
        </a-menu-item>
        <a-menu-item key="fingerprints">
          <template #icon><SafetyOutlined /></template>
          指纹
        </a-menu-item>
      </a-menu>
    </a-layout-sider>

    <a-layout>
      <a-layout-header class="topbar">
        <div class="topbar-title">
          <h1>{{ pageTitle }}</h1>
          <p>{{ pageHint }}</p>
        </div>
        <div class="topbar-actions">
          <a-select
            v-model:value="selectedCampaignId"
            class="campaign-select"
            allow-clear
            show-search
            option-filter-prop="label"
            placeholder="选择活动"
            :options="campaignOptions"
            @change="refreshCurrent"
          />
          <a-button :loading="loading.any" @click="refreshCurrent">
            <template #icon><ReloadOutlined /></template>
          </a-button>
        </div>
      </a-layout-header>

      <a-layout-content class="content">
        <a-alert
          v-if="error"
          class="error-alert"
          type="error"
          show-icon
          :message="error"
          closable
          @close="error = ''"
        />

        <section v-show="activeTab === 'overview'" class="panel">
          <div class="metric-grid">
            <div class="metric-tile"><span>总资产</span><strong>{{ dashStats.total_assets || 0 }}</strong></div>
            <div class="metric-tile"><span>今日新增</span><strong>{{ dashStats.today_new_assets || 0 }}</strong></div>
            <div class="metric-tile"><span>活跃任务</span><strong>{{ dashStats.active_work_items || 0 }}</strong></div>
            <div class="metric-tile"><span>漏洞</span><strong>{{ dashStats.vulnerabilities || 0 }}</strong></div>
          </div>
          <div class="metric-grid" style="grid-template-columns: repeat(3, 1fr)">
            <div class="metric-tile"><span>活动</span><strong>{{ dashStats.campaigns || 0 }}</strong></div>
            <div class="metric-tile"><span>批次</span><strong>{{ dashStats.batches || 0 }}</strong></div>
            <div class="metric-tile"><span>工件</span><strong>{{ dashStats.artifacts || 0 }}</strong></div>
          </div>
          <div class="split-grid">
            <div class="section-block">
              <div class="section-head"><h2>服务健康</h2></div>
              <a-descriptions size="small" :column="1">
                <a-descriptions-item label="PostgreSQL"><a-tag :color="health.postgres_ok ? 'green' : 'red'">{{ health.postgres_ok ? '正常' : '异常' }}</a-tag></a-descriptions-item>
                <a-descriptions-item label="Redis"><a-tag :color="health.redis_ok ? 'green' : 'red'">{{ health.redis_ok ? '正常' : '异常' }}</a-tag></a-descriptions-item>
                <a-descriptions-item label="Temporal"><a-tag :color="health.temporal_ok ? 'green' : 'red'">{{ health.temporal_ok ? '正常' : '异常' }}</a-tag></a-descriptions-item>
                <a-descriptions-item label="内存">{{ health.memory_percent || 0 }}%</a-descriptions-item>
                <a-descriptions-item label="磁盘">{{ health.disk_percent || 0 }}%</a-descriptions-item>
                <a-descriptions-item label="运行时间">{{ uptimeText }}</a-descriptions-item>
              </a-descriptions>
            </div>
            <div class="section-block">
              <div class="section-head"><h2>工件统计</h2></div>
              <a-table size="small" :pagination="pag6" :columns="artifactStatColumns" :data-source="artifactStats" row-key="artifact" />
            </div>
          </div>
        </section>

        <section v-show="activeTab === 'campaigns'" class="panel">
          <div class="section-head">
            <h2>活动</h2>
            <a-button type="primary" @click="openCampaignModal">
              <template #icon><PlusOutlined /></template>
              新建活动
            </a-button>
          </div>
          <a-table
            :loading="loading.campaigns"
            :columns="campaignColumns"
            :data-source="campaigns"
            :pagination="pag10"
            row-key="id"
            size="middle"
          >
            <template #bodyCell="{ column, record }">
              <template v-if="column.key === 'status'">
                <a-tag :color="statusColor(record.status)">{{ record.status }}</a-tag>
              </template>
              <template v-if="column.key === 'targets'">
                <span>{{ (record.targets || []).slice(0, 3).join(', ') }}</span>
              </template>
              <template v-if="column.key === 'actions'">
                <a-space>
                  <a-button size="small" @click="selectCampaign(record.id)">使用</a-button>
                  <a-button size="small" @click="setCampaignStatus(record, 'paused')">暂停</a-button>
                  <a-button size="small" @click="setCampaignStatus(record, 'active')">恢复</a-button>
                </a-space>
              </template>
            </template>
          </a-table>
        </section>

        <section v-show="activeTab === 'batches'" class="panel">
          <div class="section-head">
            <h2>批次</h2>
            <a-button type="primary" @click="openBatchModal">
              <template #icon><PlayCircleOutlined /></template>
              启动批次
            </a-button>
          </div>
          <a-table
            :loading="loading.batches"
            :columns="batchColumns"
            :data-source="batches"
            :pagination="pag10"
            row-key="id"
            size="middle"
          >
            <template #bodyCell="{ column, record }">
              <template v-if="column.key === 'status'">
                <a-tag :color="statusColor(record.overall_status || record.status)">
                  {{ record.overall_status || record.status }}
                </a-tag>
              </template>
              <template v-if="column.key === 'progress'">
                <a-progress
                  :percent="record.work_item_progress?.progress_percent || 0"
                  size="small"
                  :show-info="false"
                />
              </template>
              <template v-if="column.key === 'actions'">
                <a-space>
                  <a-button size="small" @click="resumeBatch(record.id)">唤醒调度</a-button>
                  <a-button size="small" @click="filterByBatch(record)">查看工作项</a-button>
                </a-space>
              </template>
            </template>
          </a-table>
        </section>

        <section v-show="activeTab === 'workItems'" class="panel">
          <div class="section-head">
            <h2>工作项</h2>
            <a-space wrap>
              <a-select v-model:value="workItemFilters.status" allow-clear placeholder="状态" class="filter-control" @change="loadWorkItems">
                <a-select-option value="pending">pending</a-select-option>
                <a-select-option value="running">running</a-select-option>
                <a-select-option value="failed">failed</a-select-option>
                <a-select-option value="retry_waiting">retry_waiting</a-select-option>
                <a-select-option value="paused">paused</a-select-option>
                <a-select-option value="completed">completed</a-select-option>
              </a-select>
              <a-input v-model:value="workItemFilters.artifact" placeholder="工件" class="filter-control" @pressEnter="loadWorkItems" />
              <a-button @click="mutateWorkItems('retry')">重试</a-button>
              <a-button @click="mutateWorkItems('pause')">暂停</a-button>
              <a-button @click="mutateWorkItems('resume')">恢复</a-button>
            </a-space>
          </div>
          <a-table
            :loading="loading.workItems"
            :columns="workItemColumns"
            :data-source="workItems"
            :pagination="pag12"
            row-key="id"
            size="small"
          >
            <template #bodyCell="{ column, record }">
              <template v-if="column.key === 'status'">
                <a-tag :color="statusColor(record.status)">{{ record.status }}</a-tag>
              </template>
              <template v-if="column.key === 'target'">
                <span class="mono truncate">{{ record.target }}</span>
              </template>
              <template v-if="column.key === 'error'">
                <a-tooltip v-if="record.error" :title="record.error">
                  <span class="error-text">{{ record.error }}</span>
                </a-tooltip>
              </template>
            </template>
          </a-table>
        </section>

        <section v-show="activeTab === 'assets'" class="panel">
          <div class="section-head">
            <h2>资产</h2>
            <a-space wrap>
              <a-select v-model:value="assetFilters.type" allow-clear placeholder="类型" class="filter-control" @change="loadResults">
                <a-select-option value="ip">ip</a-select-option>
                <a-select-option value="port">port</a-select-option>
                <a-select-option value="service">service</a-select-option>
                <a-select-option value="url">url</a-select-option>
                <a-select-option value="fingerprint">fingerprint</a-select-option>
                <a-select-option value="vulnerability">vulnerability</a-select-option>
                <a-select-option value="cve">cve</a-select-option>
                <a-select-option value="template">template</a-select-option>
              </a-select>
              <a-select v-model:value="assetFilters.status" allow-clear placeholder="状态" class="filter-control" @change="loadResults">
                <a-select-option value="observed">observed</a-select-option>
                <a-select-option value="candidate">candidate</a-select-option>
                <a-select-option value="confirmed">confirmed</a-select-option>
                <a-select-option value="noise">noise</a-select-option>
              </a-select>
              <a-input v-model:value="assetFilters.source" placeholder="来源" class="filter-control" @pressEnter="loadResults" />
              <a-button @click="loadResults">查询</a-button>
            </a-space>
          </div>
          <a-table
            :loading="loading.results"
            :columns="assetColumns"
            :data-source="results"
            :pagination="pag12"
            row-key="id"
            size="small"
          >
            <template #bodyCell="{ column, record }">
              <template v-if="column.key === 'type'">
                <a-tag>{{ record.type }}</a-tag>
              </template>
              <template v-if="column.key === 'value'">
                <span class="mono truncate">{{ record.value }}</span>
              </template>
              <template v-if="column.key === 'status'">
                <a-select
                  :value="record.status"
                  size="small"
                  class="status-select"
                  @change="(value) => updateAssetStatus(record, value)"
                >
                  <a-select-option value="observed">observed</a-select-option>
                  <a-select-option value="candidate">candidate</a-select-option>
                  <a-select-option value="confirmed">confirmed</a-select-option>
                  <a-select-option value="noise">noise</a-select-option>
                </a-select>
              </template>
            </template>
          </a-table>
        </section>

        <section v-show="activeTab === 'actions'" class="panel">
          <div class="section-head">
            <h2>动作</h2>
            <a-space wrap>
              <a-input v-model:value="planTarget" placeholder="目标" class="target-input" @pressEnter="loadPlan" />
              <a-button @click="loadPlan">生成建议</a-button>
              <a-button type="primary" @click="openActionModal">
                <template #icon><ThunderboltOutlined /></template>
                手动动作
              </a-button>
            </a-space>
          </div>
          <div v-if="planActions.length" class="section-block compact">
            <div class="section-head">
              <h2>建议动作</h2>
            </div>
            <a-table
              size="small"
              :pagination="pag5"
              :columns="planColumns"
              :data-source="planActions"
              row-key="id"
            >
              <template #bodyCell="{ column, record }">
                <template v-if="column.key === 'decision'">
                  <a-tag :color="record.decision?.schedule === 'now' ? 'green' : 'blue'">{{ record.decision?.schedule || '-' }}</a-tag>
                </template>
                <template v-if="column.key === 'actions'">
                  <a-button size="small" @click="startPlannedAction(record)">执行</a-button>
                </template>
              </template>
            </a-table>
          </div>
          <a-table
            :loading="loading.actions"
            :columns="actionColumns"
            :data-source="actions"
            :pagination="pag10"
            row-key="id"
            size="small"
          >
            <template #bodyCell="{ column, record }">
              <template v-if="column.key === 'status'">
                <a-tag :color="statusColor(record.status)">{{ record.status }}</a-tag>
              </template>
              <template v-if="column.key === 'target'">
                <span class="mono truncate">{{ record.target }}</span>
              </template>
            </template>
          </a-table>
        </section>

        <section v-show="activeTab === 'policies'" class="panel">
          <div class="section-head">
            <h2>策略</h2>
            <a-button type="primary" @click="openPolicyModal()"><template #icon><PlusOutlined /></template>新建策略</a-button>
          </div>
          <a-table :loading="loading.policies" :columns="policyColumns" :data-source="policies" :pagination="pag10" row-key="id" size="middle">
            <template #bodyCell="{ column, record }">
              <template v-if="column.key === 'actions'">
                <a-space>
                  <a-button size="small" @click="openPolicyModal(record)">编辑</a-button>
                  <a-button size="small" danger @click="deletePolicyItem(record.id)">删除</a-button>
                </a-space>
              </template>
            </template>
          </a-table>
        </section>

        <section v-show="activeTab === 'exports'" class="panel">
          <div class="section-head"><h2>导出</h2></div>
          <a-form layout="inline" class="export-form">
            <a-form-item label="批次"><a-select v-model:value="exportBatchId" :options="batchExportOptions" placeholder="选择批次" style="width:400px" /></a-form-item>
            <a-form-item label="类型"><a-select v-model:value="exportType" :options="exportTypeOptions" style="width:140px" /></a-form-item>
            <a-form-item label="格式"><a-select v-model:value="exportFormat" :options="[{label:'CSV',value:'csv'},{label:'JSON',value:'json'}]" style="width:120px" /></a-form-item>
            <a-form-item><a-button type="primary" @click="doExport" :disabled="!exportBatchId">下载</a-button></a-form-item>
          </a-form>
        </section>

        <section v-show="activeTab === 'monitors'" class="panel">
          <div class="section-head">
            <h2>监控</h2>
            <a-button type="primary" @click="monitorModal.open = true"><template #icon><PlusOutlined /></template>新建监控</a-button>
          </div>
          <a-table :loading="loading.monitors" :columns="monitorColumns" :data-source="monitors" :pagination="pag10" row-key="id" size="middle">
            <template #bodyCell="{ column, record }">
              <template v-if="column.key === 'status'"><a-tag :color="record.status==='active'?'green':'orange'">{{ record.status }}</a-tag></template>
              <template v-if="column.key === 'actions'">
                <a-space>
                  <a-button size="small" @click="toggleMonitor(record)">{{ record.status === 'active' ? '暂停' : '恢复' }}</a-button>
                  <a-button size="small" danger @click="deleteMonitorItem(record.id)">删除</a-button>
                </a-space>
              </template>
            </template>
          </a-table>
        </section>

        <section v-show="activeTab === 'fingerprints'" class="panel">
          <div class="section-head">
            <h2>指纹</h2>
            <a-button type="primary" @click="fpModal.open = true"><template #icon><PlusOutlined /></template>新建指纹</a-button>
          </div>
          <a-table :loading="loading.fingerprints" :columns="fpColumns" :data-source="fingerprints" :pagination="pag10" row-key="id" size="middle">
            <template #bodyCell="{ column, record }">
              <template v-if="column.key === 'actions'">
                <a-button size="small" danger @click="deleteFpItem(record.id)">删除</a-button>
              </template>
            </template>
          </a-table>
        </section>

        <section v-show="activeTab === 'artifacts'" class="panel">
          <div class="section-head">
            <h2>工件</h2>
          </div>
          <a-table
            :loading="loading.artifacts"
            :columns="artifactColumns"
            :data-source="artifacts"
            :pagination="pag12"
            row-key="name"
            size="middle"
          >
            <template #bodyCell="{ column, record }">
              <template v-if="column.key === 'risk'">
                <a-tag :color="riskColor(record.descriptor?.risk)">{{ record.descriptor?.risk || '-' }}</a-tag>
              </template>
              <template v-if="column.key === 'produces'">
                <a-space wrap>
                  <a-tag v-for="item in record.descriptor?.produces || []" :key="item">{{ item }}</a-tag>
                </a-space>
              </template>
            </template>
          </a-table>
        </section>
      </a-layout-content>
    </a-layout>
  </a-layout>

  <a-modal v-model:open="campaignModal.open" title="新建活动" @ok="createCampaign" :confirm-loading="campaignModal.loading">
    <a-form layout="vertical">
      <a-form-item label="名称">
        <a-input v-model:value="campaignModal.name" placeholder="例如 example 外部攻击面" />
      </a-form-item>
      <a-form-item label="描述">
        <a-textarea v-model:value="campaignModal.description" :rows="2" />
      </a-form-item>
      <a-form-item label="目标">
        <a-textarea v-model:value="campaignModal.targets" :rows="5" placeholder="每行一个域名、IP 或 CIDR" />
      </a-form-item>
    </a-form>
  </a-modal>

  <a-modal v-model:open="batchModal.open" title="启动批次" @ok="startBatch" :confirm-loading="batchModal.loading">
    <a-form layout="vertical">
      <a-form-item label="活动 ID">
        <a-input v-model:value="batchModal.campaignId" />
      </a-form-item>
      <a-form-item label="目标">
        <a-textarea v-model:value="batchModal.targets" :rows="5" placeholder="每行一个目标" />
      </a-form-item>
      <a-form-item label="端口">
        <a-input v-model:value="batchModal.ports" placeholder="80,443,8080" />
      </a-form-item>
      <a-form-item>
        <a-checkbox v-model:checked="batchModal.runPlannedDAG">启用 Planner 后续动作</a-checkbox>
      </a-form-item>
    </a-form>
  </a-modal>

  <a-modal v-model:open="policyModal.open" :title="policyModal.editId ? '编辑策略' : '新建策略'" @ok="savePolicy" :confirm-loading="policyModal.loading">
    <a-form layout="vertical">
      <a-form-item label="名称"><a-input v-model:value="policyModal.name" /></a-form-item>
      <a-form-item label="描述"><a-input v-model:value="policyModal.description" /></a-form-item>
      <a-form-item label="端口"><a-input v-model:value="policyModal.ports" placeholder="80,443,8080" /></a-form-item>
      <a-form-item label="线程"><a-input-number v-model:value="policyModal.threads" :min="0" :max="10000" style="width:100%" /></a-form-item>
      <a-form-item label="Spray 字典"><a-input v-model:value="policyModal.spray_dict" placeholder="默认 SDK 字典" /></a-form-item>
      <a-form-item label="Nuclei Tags"><a-input v-model:value="policyModal.nuclei_tags" placeholder="cve,misconfig,exposure" /></a-form-item>
    </a-form>
  </a-modal>

  <a-modal v-model:open="monitorModal.open" title="新建监控" @ok="saveMonitor" :confirm-loading="monitorModal.loading">
    <a-form layout="vertical">
      <a-form-item label="名称"><a-input v-model:value="monitorModal.name" /></a-form-item>
      <a-form-item label="活动"><a-select v-model:value="monitorModal.campaign_id" :options="campaignOptions" placeholder="选择活动" /></a-form-item>
      <a-form-item label="端口"><a-input v-model:value="monitorModal.ports" placeholder="80,443,8080" /></a-form-item>
      <a-form-item label="间隔(小时)"><a-input-number v-model:value="monitorModal.interval_hours" :min="1" :max="720" style="width:100%" /></a-form-item>
    </a-form>
  </a-modal>

  <a-modal v-model:open="fpModal.open" title="新建指纹" @ok="saveFingerprint" :confirm-loading="fpModal.loading">
    <a-form layout="vertical">
      <a-form-item label="名称"><a-input v-model:value="fpModal.name" /></a-form-item>
      <a-form-item label="类型"><a-select v-model:value="fpModal.type" :options="[{label:'HTTP',value:'http'},{label:'TCP',value:'tcp'}]" /></a-form-item>
      <a-form-item label="规则"><a-textarea v-model:value="fpModal.rule" :rows="4" placeholder='JSON 格式，如 {"body":"nginx"}' /></a-form-item>
      <a-form-item label="描述"><a-input v-model:value="fpModal.description" /></a-form-item>
    </a-form>
  </a-modal>

  <a-modal v-model:open="actionModal.open" title="手动动作" @ok="startManualAction" :confirm-loading="actionModal.loading">
    <a-form layout="vertical">
      <a-form-item label="工件">
        <a-select v-model:value="actionModal.artifact" :options="artifactNameOptions" placeholder="选择工件" />
      </a-form-item>
      <a-form-item label="目标">
        <a-input v-model:value="actionModal.target" />
      </a-form-item>
      <a-form-item label="输入 JSON">
        <a-textarea v-model:value="actionModal.input" :rows="7" />
      </a-form-item>
    </a-form>
  </a-modal>
</template>

<script setup>
import { computed, onMounted, reactive, ref, watch } from 'vue';
import { message } from 'ant-design-vue';
import {
  BarsOutlined, DashboardOutlined, DatabaseOutlined, DownloadOutlined,
  FileProtectOutlined, FolderOpenOutlined, PartitionOutlined,
  PlayCircleOutlined, PlusOutlined, ReloadOutlined, SafetyOutlined,
  SyncOutlined, ThunderboltOutlined, ToolOutlined,
} from '@ant-design/icons-vue';
import { api, splitLines } from './api';

const selectedKeys = ref(['overview']);
const activeTab = computed(() => selectedKeys.value[0] || 'overview');
const selectedCampaignId = ref('');
const error = ref('');

const pag6  = reactive({ pageSize: 6,  showSizeChanger: true, pageSizeOptions: [6,12,20,50] });
const pag5  = reactive({ pageSize: 5,  showSizeChanger: true, pageSizeOptions: [5,10,20,50] });
const pag10 = reactive({ pageSize: 10, showSizeChanger: true, pageSizeOptions: [10,20,50,100] });
const pag12 = reactive({ pageSize: 12, showSizeChanger: true, pageSizeOptions: [12,20,50,100] });

const campaigns = ref([]);
const batches = ref([]);
const workItems = ref([]);
const results = ref([]);
const actions = ref([]);
const artifacts = ref([]);
const summary = ref(null);
const artifactStats = ref([]);
const planActions = ref([]);
const planTarget = ref('');

const loading = reactive({
  campaigns: false, batches: false, workItems: false, results: false,
  actions: false, artifacts: false, summary: false,
  policies: false, monitors: false, fingerprints: false,
  any: false,
});

const loadingKeys = ['campaigns', 'batches', 'workItems', 'results', 'actions', 'artifacts', 'summary'];

const workItemFilters = reactive({ status: undefined, artifact: '', batch_id: '' });
const assetFilters = reactive({ type: undefined, status: undefined, source: '' });

const campaignModal = reactive({ open: false, loading: false, name: '', description: '', targets: '' });
const batchModal = reactive({ open: false, loading: false, campaignId: '', targets: '', ports: '80,443', runPlannedDAG: true });
const actionModal = reactive({ open: false, loading: false, artifact: '', target: '', input: '{}' });
const policyModal = reactive({ open: false, loading: false, editId: '', name: '', description: '', ports: '80,443', threads: 0, spray_dict: '', nuclei_tags: '' });
const monitorModal = reactive({ open: false, loading: false, name: '', campaign_id: undefined, ports: '80,443', interval_hours: 24 });
const fpModal = reactive({ open: false, loading: false, name: '', type: 'http', rule: '{}', description: '' });

const policies = ref([]);
const fingerprints = ref([]);
const monitors = ref([]);
const dashStats = ref({});
const health = ref({});
const exportBatchId = ref(undefined);
const exportType = ref('url');
const exportFormat = ref('csv');

const pageMeta = {
  overview: ['总览', '当前活动的运行进度、吞吐和工件统计'],
  campaigns: ['活动', '管理目标集合和扫描阶段'],
  batches: ['批次', '启动和观察批量扫描'],
  workItems: ['工作项', '查看调度队列、失败原因和恢复操作'],
  assets: ['资产', '按类型、状态和来源查看标准化资产'],
  actions: ['动作', '查看 Planner 建议并执行单个工件动作'],
  artifacts: ['工件', '浏览当前注册的工件能力和风险属性'],
  policies: ['策略', '管理可复用的扫描配置模板'],
  exports: ['导出', '按批次和类型导出资产数据'],
  monitors: ['监控', '管理定期自动重扫任务'],
  fingerprints: ['指纹', '管理 Web 指纹识别规则'],
};

const pageTitle = computed(() => pageMeta[activeTab.value]?.[0] || 'Weave');
const pageHint = computed(() => pageMeta[activeTab.value]?.[1] || '');

const campaignOptions = computed(() => campaigns.value.map((item) => ({
  label: `${item.name || item.id} (${item.status})`,
  value: item.id,
})));

const artifactNameOptions = computed(() => artifacts.value.map((item) => ({ label: item.name, value: item.name })));

const metrics = computed(() => {
  const overall = summary.value?.overall || {};
  return [
    { label: '工作项', value: summary.value?.total ?? 0 },
    { label: '运行中', value: overall.running ?? 0 },
    { label: '失败', value: (overall.failed ?? 0) + (overall.dead ?? 0) },
    { label: '进度', value: `${overall.progress_percent ?? 0}%` },
  ];
});

const uptimeText = computed(() => {
  const s = health.value.uptime_seconds || 0;
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
  return h > 0 ? `${h}h ${m}m` : `${m}m`;
});

const batchExportOptions = computed(() => batches.value.map(b => ({ label: `${b.id?.slice(-20)} (${b.status})`, value: b.id })));
const exportTypeOptions = [{ label: 'IP', value: 'ip' }, { label: 'Port', value: 'port' }, { label: 'Service', value: 'service' }, { label: 'URL', value: 'url' }];

const summaryRows = computed(() => Object.entries(summary.value?.by_status || {}).map(([key, value]) => ({ key, value })));

const campaignColumns = [
  { title: '名称', dataIndex: 'name', key: 'name' },
  { title: '状态', dataIndex: 'status', key: 'status', width: 120 },
  { title: '阶段', dataIndex: 'phase', key: 'phase', width: 140 },
  { title: '目标', key: 'targets' },
  { title: '更新时间', dataIndex: 'updated_at', key: 'updated_at', width: 190 },
  { title: '操作', key: 'actions', width: 220 },
];

const batchColumns = [
  { title: 'ID', dataIndex: 'id', key: 'id', ellipsis: true },
  { title: '目标', dataIndex: 'target', key: 'target', ellipsis: true },
  { title: '端口', dataIndex: 'ports', key: 'ports', width: 140 },
  { title: '状态', key: 'status', width: 120 },
  { title: '进度', key: 'progress', width: 160 },
  { title: '操作', key: 'actions', width: 210 },
];

const workItemColumns = [
  { title: '类型', dataIndex: 'type', key: 'type', width: 150 },
  { title: '工件', dataIndex: 'artifact', key: 'artifact', width: 110 },
  { title: '目标', key: 'target', ellipsis: true },
  { title: '状态', key: 'status', width: 130 },
  { title: '尝试', dataIndex: 'attempts', key: 'attempts', width: 80 },
  { title: '错误', key: 'error', ellipsis: true },
];

const assetColumns = [
  { title: '类型', key: 'type', width: 130 },
  { title: '值', key: 'value', ellipsis: true },
  { title: '来源', dataIndex: 'source', key: 'source', width: 120 },
  { title: '严重性', dataIndex: 'severity', key: 'severity', width: 100 },
  { title: '状态', key: 'status', width: 150 },
  { title: '最后发现', dataIndex: 'last_seen', key: 'last_seen', width: 190 },
];

const actionColumns = [
  { title: '工件', dataIndex: 'artifact', key: 'artifact', width: 120 },
  { title: '目标', key: 'target', ellipsis: true },
  { title: '原因', dataIndex: 'reason', key: 'reason', ellipsis: true },
  { title: '状态', key: 'status', width: 130 },
  { title: '工作流', dataIndex: 'workflow_id', key: 'workflow_id', ellipsis: true },
];

const planColumns = [
  { title: '工件', dataIndex: 'artifact', key: 'artifact', width: 120 },
  { title: '原因', dataIndex: 'reason', key: 'reason', ellipsis: true },
  { title: '风险', dataIndex: 'risk', key: 'risk', width: 90 },
  { title: '调度', key: 'decision', width: 100 },
  { title: '操作', key: 'actions', width: 90 },
];

const artifactColumns = [
  { title: '名称', dataIndex: 'name', key: 'name', width: 140 },
  { title: '风险', key: 'risk', width: 100 },
  { title: '输入', dataIndex: ['descriptor', 'consumes'], key: 'consumes' },
  { title: '输出', key: 'produces' },
  { title: '说明', dataIndex: ['descriptor', 'description'], key: 'description' },
];

const summaryColumns = [
  { title: '状态', dataIndex: 'key', key: 'key' },
  { title: '数量', dataIndex: 'value', key: 'value', width: 120 },
];

const artifactStatColumns = [
  { title: '工件', dataIndex: 'artifact', key: 'artifact' },
  { title: '请求', dataIndex: 'requests', key: 'requests', width: 100 },
  { title: '结果', dataIndex: 'results', key: 'results', width: 100 },
  { title: '错误', dataIndex: 'errors', key: 'errors', width: 100 },
];

const policyColumns = [
  { title: '名称', dataIndex: 'name', key: 'name' },
  { title: '端口', dataIndex: 'ports', key: 'ports' },
  { title: '线程', dataIndex: 'threads', key: 'threads', width: 80 },
  { title: '字典', dataIndex: 'spray_dict', key: 'spray_dict', ellipsis: true },
  { title: 'Tags', dataIndex: 'nuclei_tags', key: 'nuclei_tags', ellipsis: true },
  { title: '操作', key: 'actions', width: 150 },
];

const monitorColumns = [
  { title: '名称', dataIndex: 'name', key: 'name' },
  { title: '活动', dataIndex: 'campaign_id', key: 'campaign_id', ellipsis: true },
  { title: '端口', dataIndex: 'ports', key: 'ports' },
  { title: '间隔(h)', dataIndex: 'interval_hours', key: 'interval_hours', width: 90 },
  { title: '状态', key: 'status', width: 90 },
  { title: '次数', dataIndex: 'run_count', key: 'run_count', width: 70 },
  { title: '操作', key: 'actions', width: 150 },
];

const fpColumns = [
  { title: '名称', dataIndex: 'name', key: 'name' },
  { title: '类型', dataIndex: 'type', key: 'type', width: 80 },
  { title: '描述', dataIndex: 'description', key: 'description', ellipsis: true },
  { title: '操作', key: 'actions', width: 100 },
];

watch(activeTab, () => refreshCurrent());
watch(selectedCampaignId, (value) => {
  batchModal.campaignId = value || '';
  refreshCurrent();
});

onMounted(async () => {
  await Promise.all([loadCampaigns(), loadArtifacts()]);
  await refreshCurrent();
});

async function capture(name, fn) {
  loading[name] = true;
  loading.any = true;
  error.value = '';
  try {
    return await fn();
  } catch (err) {
    error.value = err.message || String(err);
    throw err;
  } finally {
    loading[name] = false;
    loading.any = loadingKeys.some((key) => loading[key]);
  }
}

function paramsWithCampaign(extra = {}) {
  return { campaign_id: selectedCampaignId.value, ...extra };
}

async function refreshCurrent() {
  const loaders = {
    overview: () => Promise.all([loadSummary(), loadStatsSummary(), loadDashboard(), loadHealth()]),
    campaigns: loadCampaigns, batches: loadBatches,
    workItems: loadWorkItems, assets: loadResults,
    actions: loadActions, artifacts: loadArtifacts,
    policies: loadPolicies, monitors: loadMonitors, fingerprints: loadFingerprints,
    exports: loadBatches,
  };
  await loaders[activeTab.value]?.();
}

async function loadCampaigns() {
  await capture('campaigns', async () => {
    const data = await api.listCampaigns({ limit: 100 });
    campaigns.value = data.campaigns || [];
  });
}

async function loadArtifacts() {
  await capture('artifacts', async () => {
    const data = await api.listArtifacts();
    artifacts.value = data.artifacts || [];
  });
}

async function loadSummary() {
  await capture('summary', async () => {
    summary.value = await api.workItemSummary(paramsWithCampaign());
  });
}

async function loadStatsSummary() {
  const data = await api.statsSummary(paramsWithCampaign());
  artifactStats.value = data.summary || [];
}

async function loadBatches() {
  await capture('batches', async () => {
    const data = await api.listBatches(paramsWithCampaign({ limit: 100 }));
    batches.value = data.batches || [];
  });
}

async function loadWorkItems() {
  await capture('workItems', async () => {
    const data = await api.listWorkItems(paramsWithCampaign({
      limit: 500,
      status: workItemFilters.status,
      artifact: workItemFilters.artifact,
      batch_id: workItemFilters.batch_id,
    }));
    workItems.value = data.work_items || [];
  });
}

async function loadResults() {
  await capture('results', async () => {
    const data = await api.listResults(paramsWithCampaign({
      limit: 500,
      type: assetFilters.type,
      status: assetFilters.status,
      source: assetFilters.source,
    }));
    results.value = data.results || [];
  });
}

async function loadActions() {
  await capture('actions', async () => {
    const data = await api.listActions(paramsWithCampaign({ raw_input: false }));
    actions.value = data.actions || [];
  });
}

async function loadPlan() {
  if (!planTarget.value.trim()) {
    message.warning('请输入目标');
    return;
  }
  const data = await api.plan(paramsWithCampaign({ target: planTarget.value.trim() }));
  planActions.value = data.actions || [];
}

function openCampaignModal() {
  Object.assign(campaignModal, { open: true, loading: false, name: '', description: '', targets: '' });
}

async function createCampaign() {
  if (!campaignModal.name.trim()) {
    message.warning('请输入活动名称');
    return;
  }
  campaignModal.loading = true;
  try {
    const created = await api.createCampaign({
      name: campaignModal.name.trim(),
      description: campaignModal.description.trim(),
      targets: splitLines(campaignModal.targets),
    });
    selectedCampaignId.value = created.id;
    campaignModal.open = false;
    message.success('活动已创建');
    await loadCampaigns();
  } catch (err) {
    error.value = err.message;
  } finally {
    campaignModal.loading = false;
  }
}

function selectCampaign(id) {
  selectedCampaignId.value = id;
  selectedKeys.value = ['overview'];
}

async function setCampaignStatus(record, status) {
  await api.updateCampaignStatus(record.id, status);
  message.success('状态已更新');
  await loadCampaigns();
}

async function openBatchModal() {
  let current = campaigns.value.find((item) => item.id === selectedCampaignId.value);
  if (selectedCampaignId.value) {
    try {
      const data = await api.getCampaign(selectedCampaignId.value);
      current = data.campaign || current;
    } catch (err) {
      error.value = err.message || String(err);
    }
  }
  Object.assign(batchModal, {
    open: true,
    loading: false,
    campaignId: selectedCampaignId.value || '',
    targets: (current?.targets || []).join('\n'),
    ports: '80,443',
    runPlannedDAG: true,
  });
}

async function startBatch() {
  const targets = splitLines(batchModal.targets);
  if (!targets.length || !batchModal.ports.trim()) {
    message.warning('目标和端口不能为空');
    return;
  }
  batchModal.loading = true;
  try {
    const result = await api.startBatch({
      campaign_id: batchModal.campaignId.trim(),
      targets,
      ports: batchModal.ports.trim(),
      run_planned_dag: batchModal.runPlannedDAG,
    });
    selectedCampaignId.value = result.campaign_id;
    batchModal.open = false;
    selectedKeys.value = ['batches'];
    message.success('批次已启动');
    await Promise.all([loadCampaigns(), loadBatches()]);
  } catch (err) {
    error.value = err.message;
  } finally {
    batchModal.loading = false;
  }
}

async function resumeBatch(id) {
  await api.resumeBatchScheduler(id, { run_planned_dag: true });
  message.success('调度器已唤醒');
  await loadBatches();
}

function filterByBatch(record) {
  selectedCampaignId.value = record.campaign_id;
  workItemFilters.batch_id = record.id;
  selectedKeys.value = ['workItems'];
}

async function mutateWorkItems(action) {
  const payload = {
    campaign_id: selectedCampaignId.value,
    batch_id: workItemFilters.batch_id,
    status: workItemFilters.status,
    artifact: workItemFilters.artifact,
    limit: 1000,
  };
  const result = await api.mutateWorkItems(action, payload);
  message.success(`已处理 ${result.updated || result.total || 0} 个工作项`);
  await loadWorkItems();
}

async function updateAssetStatus(record, status) {
  await api.updateResultStatus(record.id, status);
  record.status = status;
  message.success('资产状态已更新');
}

function openActionModal() {
  Object.assign(actionModal, {
    open: true,
    loading: false,
    artifact: artifacts.value[0]?.name || '',
    target: planTarget.value || '',
    input: '{}',
  });
}

async function startManualAction() {
  let input;
  try {
    input = JSON.parse(actionModal.input || '{}');
  } catch {
    message.error('输入 JSON 不合法');
    return;
  }
  actionModal.loading = true;
  try {
    await api.startAction({
      artifact: actionModal.artifact,
      target: actionModal.target,
      campaign_id: selectedCampaignId.value,
      input,
    });
    actionModal.open = false;
    message.success('动作已提交');
    await loadActions();
  } catch (err) {
    error.value = err.message;
  } finally {
    actionModal.loading = false;
  }
}

async function startPlannedAction(record) {
  await api.startAction({
    artifact: record.artifact,
    target: record.target,
    campaign_id: selectedCampaignId.value || record.campaign_id,
    input: record.input || {},
  });
  message.success('建议动作已提交');
  await loadActions();
}

function statusColor(status) {
  const value = String(status || '').toLowerCase();
  if (['active', 'running', 'dispatching'].includes(value)) return 'blue';
  if (['completed', 'done', 'confirmed'].includes(value)) return 'green';
  if (['failed', 'dead', 'error'].includes(value)) return 'red';
  if (['paused', 'retry_waiting', 'pending'].includes(value)) return 'gold';
  if (['noise', 'cancelled', 'skipped'].includes(value)) return 'default';
  return 'default';
}

function riskColor(risk) {
  const value = String(risk || '').toLowerCase();
  if (value === 'high') return 'red';
  if (value === 'medium') return 'orange';
  if (value === 'low') return 'green';
  return 'default';
}

// Dashboard
async function loadDashboard() { dashStats.value = await api.dashboardStats(paramsWithCampaign()); }
async function loadHealth() { health.value = await api.dashboardHealth(); }

// Policies
async function loadPolicies() {
  await capture('policies', async () => { policies.value = (await api.listPolicies()).policies || []; });
}
function openPolicyModal(record) {
  if (record) {
    Object.assign(policyModal, { open: true, loading: false, editId: record.id, name: record.name, description: record.description, ports: record.ports, threads: record.threads, spray_dict: record.spray_dict, nuclei_tags: record.nuclei_tags });
  } else {
    Object.assign(policyModal, { open: true, loading: false, editId: '', name: '', description: '', ports: '80,443', threads: 0, spray_dict: '', nuclei_tags: '' });
  }
}
async function savePolicy() {
  policyModal.loading = true;
  try {
    const body = { name: policyModal.name, description: policyModal.description, ports: policyModal.ports, threads: policyModal.threads, spray_dict: policyModal.spray_dict, nuclei_tags: policyModal.nuclei_tags };
    policyModal.editId ? await api.updatePolicy(policyModal.editId, body) : await api.createPolicy(body);
    policyModal.open = false;
    message.success('策略已保存');
    await loadPolicies();
  } catch (err) { error.value = err.message; } finally { policyModal.loading = false; }
}
async function deletePolicyItem(id) {
  await api.deletePolicy(id);
  message.success('策略已删除');
  await loadPolicies();
}

// Exports
function doExport() {
  if (exportBatchId.value && exportType.value) {
    api.exportBatch(exportBatchId.value, exportType.value, exportFormat.value);
    message.success('导出已开始');
  }
}

// Monitors
async function loadMonitors() {
  await capture('monitors', async () => { monitors.value = (await api.listMonitors()).monitors || []; });
}
async function saveMonitor() {
  monitorModal.loading = true;
  try {
    await api.createMonitor({ name: monitorModal.name, campaign_id: monitorModal.campaign_id, ports: monitorModal.ports, interval_hours: monitorModal.interval_hours });
    monitorModal.open = false;
    message.success('监控已创建');
    await loadMonitors();
  } catch (err) { error.value = err.message; } finally { monitorModal.loading = false; }
}
async function toggleMonitor(record) {
  if (record.status === 'active') { await api.pauseMonitor(record.id); message.success('已暂停'); }
  else { await api.resumeMonitor(record.id); message.success('已恢复'); }
  await loadMonitors();
}
async function deleteMonitorItem(id) { await api.deleteMonitor(id); message.success('监控已删除'); await loadMonitors(); }

// Fingerprints
async function loadFingerprints() {
  await capture('fingerprints', async () => { fingerprints.value = (await api.listFingerprints()).fingerprints || []; });
}
async function saveFingerprint() {
  fpModal.loading = true;
  try {
    await api.createFingerprint({ name: fpModal.name, type: fpModal.type, rule: fpModal.rule, description: fpModal.description });
    fpModal.open = false;
    message.success('指纹已创建');
    await loadFingerprints();
  } catch (err) { error.value = err.message; } finally { fpModal.loading = false; }
}
async function deleteFpItem(id) { await api.deleteFingerprint(id); message.success('指纹已删除'); await loadFingerprints(); }
</script>
