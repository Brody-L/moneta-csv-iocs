class ScannerContext {
public:
	enum class MemorySelection_t {
		Invalid,
		Block,
		All,
		Ioc,
		Referenced
	};

	uint64_t GetFlags() const { return this->Flags; }
	MemorySelection_t GetMst() const { return this->Mst; }
	const uint8_t* GetAddress() const { return this->Address; }
	const uint32_t GetRegionSize() const { return this->RegionSize; }
	const uint64_t GetFilters() const { return this->Filters; }
	const std::wstring& GetIocCsvPath() const { return this->IocCsvPath; }
	bool HasIocCsvPath() const { return !this->IocCsvPath.empty(); }
	ScannerContext(uint64_t qwFlags, MemorySelection_t Mst, uint8_t* pAddress, uint32_t dwRegionSize, uint64_t qwFilters, std::wstring iocCsvPath = L"")
		: Flags(qwFlags), Mst(Mst), Address(pAddress), RegionSize(dwRegionSize), Filters(qwFilters), IocCsvPath(std::move(iocCsvPath)) {}
protected:
	const uint64_t Flags;
	const MemorySelection_t Mst;
	const uint8_t* Address;
	const uint32_t RegionSize;
	const uint64_t Filters;
	const std::wstring IocCsvPath;
};