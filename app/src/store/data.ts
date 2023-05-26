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
    },
    realPriData:[] as any,
    paginationPri: {
      totalCount: 0,
      currentPage: 1,
      pageSize: 10,
      searchInput: '',
    },
    email:''
  }),
  actions: {
    async getTableData() {
      const param = {
        visibility: this.visibility,
      };
      const res = await queryAllData(param);
      this.realData = res;
      this.tableData = this.realData.slice(
        (this.pagination.currentPage - 1) * this.pagination.pageSize,
        this.pagination.currentPage * this.pagination.pageSize
      );
      if (this.pagination.searchInput) {
        this.tableData = this.realData.filter((item: any) =>
        item.name.toLowerCase().includes(this.pagination.searchInput)
      );
        this.pagination.totalCount = this.tableData.length;
      } else {
        this.pagination.totalCount = this.realData.length;
      }

      this.pgpData = this.realData.filter(
        (item: any) => item.key_type === 'pgp'
      ).length;
      this.x509Data = this.realData.filter(
        (item: any) => item.key_type === 'x509'
      ).length;
    },
    async getPriTableData() {
      const param = {
        visibility: this.visib,
      };
      const res = await queryAllData(param);
      this.realPriData = res;
      this.tablePriData = this.realPriData.slice(
        (this.paginationPri.currentPage - 1) * this.paginationPri.pageSize,
        this.paginationPri.currentPage * this.paginationPri.pageSize
      );
      if (this.paginationPri.searchInput) {
        this.tablePriData = this.realPriData.filter(
          (item: any) => item.name.toLowerCase().includes(this.paginationPri.searchInput)
        );
        this.paginationPri.totalCount = this.tablePriData.length;
      } else {
        this.paginationPri.totalCount = this.realPriData.length;
      }

      this.pgpPriData = this.realPriData.filter(
        (item: any) => item.key_type === 'pgp'
      ).length;
      this.x509PriData = this.realPriData.filter(
        (item: any) => item.key_type === 'x509'
      ).length;
    },
  },

  getters: {
  },
});
