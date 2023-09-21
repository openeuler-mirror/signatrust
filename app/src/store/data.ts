import { defineStore } from 'pinia';
import { queryAllData } from '@/api/show';
export const useDataStore = defineStore('data', {
  state: () => ({
    startTime: new Date().getTime() - (365 / 2) * 24 * 3600 * 1000,
    endTime: new Date().getTime(),
    countWay: 'month',
    tableData: [] as any,
    visibility: 'public',
    visib: 'private',
    tablePriData: [] as any,
    pgpData: '',
    x509Data: '',
    pgpPriData: '',
    x509PriData: '',
    realData: [] as any,
    pagination: {
      totalCount: 0,
      currentPage: 1,
      pageSize: 10,
      searchInput: '',
      select: 'name',
    },
    realPriData: [] as any,
    paginationPri: {
      totalCount: 0,
      currentPage: 1,
      pageSize: 10,
      searchInput: '',
      select: 'name',
    },
    email: '',
    param: {},
    paramPri: {},
  }),
  actions: {
    async getTableData() {
      if (this.pagination.searchInput && this.pagination.select === 'name') {
        this.param = {
          visibility: this.visibility,
          page_size: this.pagination.pageSize,
          page_number: this.pagination.currentPage,
          name: this.pagination.searchInput,
        };
      } else if (
        this.pagination.searchInput &&
        this.pagination.select === 'description'
      ) {
        this.param = {
          visibility: this.visibility,
          page_size: this.pagination.pageSize,
          page_number: this.pagination.currentPage,
          description: this.pagination.searchInput,
        };
      } else {
        this.param = {
          visibility: this.visibility,
          page_size: this.pagination.pageSize,
          page_number: this.pagination.currentPage,
        };
      }
      const res = await queryAllData(this.param);
      this.realData = res;
      this.tableData = this.realData.data;
      this.pagination.totalCount = this.realData.meta.total_count;
      this.pgpData = this.realData.meta.total_count;
    
    },
    async getPriTableData() {
      if (this.paginationPri.searchInput && this.paginationPri.select === 'name') {
        this.paramPri = {
          visibility: this.visib,
          page_size: this.paginationPri.pageSize,
          page_number: this.paginationPri.currentPage,
          name: this.paginationPri.searchInput,
        };
      } else if (
        this.paginationPri.searchInput &&
        this.paginationPri.select === 'description'
      ) {
        this.paramPri = {
          visibility: this.visib,
          page_size: this.paginationPri.pageSize,
          page_number: this.paginationPri.currentPage,
          description: this.paginationPri.searchInput,
        };
      } else {
        this.paramPri = {
          visibility: this.visib,
          page_size: this.paginationPri.pageSize,
          page_number: this.paginationPri.currentPage,
        };
      }
      const res = await queryAllData(this.paramPri);
      this.realPriData = res;
      this.tablePriData = this.realPriData.data
      this.paginationPri.totalCount = this.realPriData.meta.total_count;
      this.pgpPriData = this.realPriData.meta.total_count;
    },
  },

  getters: {},
});
