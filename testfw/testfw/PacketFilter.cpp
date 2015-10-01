/******************************************************************************
  PacketFilter.cpp - PacketFilter class implemenation.

  Original WFP source code by Mahesh S
  swatkat_thinkdigit@yahoo.co.in
  http://swatrant.blogspot.com/
  
  Modified for OpenVPN by ValdikSS
******************************************************************************/

#include "stdafx.h"
#include "PacketFilter.h"
#include "openvpn-plugin.h"
#include <iphlpapi.h>
#include <time.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "rpcrt4.lib")
#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))


/******************************************************************************
PacketFilter::PacketFilter() - Constructor
*******************************************************************************/
PacketFilter::PacketFilter()
{
    try
    {
        // Initialize member variables.
        m_hEngineHandle = NULL;
        ::ZeroMemory( &m_subLayerGUID, sizeof( GUID ) );
    }
    catch(...)
    {
    }
}

/******************************************************************************
PacketFilter::~PacketFilter() - Destructor
*******************************************************************************/
PacketFilter::~PacketFilter()
{
    try
    {
        // Stop firewall before closing.
        StopFirewall();
    }
    catch(...)
    {
    }
}

/******************************************************************************
PacketFilter::CreateDeleteInterface - This method creates or deletes a packet
                                      filter interface.
*******************************************************************************/
DWORD PacketFilter::CreateDeleteInterface( bool bCreate )
{
    DWORD dwFwAPiRetCode = ERROR_BAD_COMMAND;
    try
    {
        if( bCreate )
        {
			FWPM_SESSION0 session = {0};
			session.flags = FWPM_SESSION_FLAG_DYNAMIC;

            // Create packet filter interface.
            dwFwAPiRetCode =  ::FwpmEngineOpen0( NULL,
                                                 RPC_C_AUTHN_WINNT,
                                                 NULL,
                                                 &session,
                                                 &m_hEngineHandle );
        }
        else
        {
            if( NULL != m_hEngineHandle )
            {
                // Close packet filter interface.
                dwFwAPiRetCode = ::FwpmEngineClose0( m_hEngineHandle );
                m_hEngineHandle = NULL;
            }
        }
    }
    catch(...)
    {
    }
    return dwFwAPiRetCode;
}

/******************************************************************************
PacketFilter::BindUnbindInterface - This method binds to or unbinds from a
                                    packet filter interface.
*******************************************************************************/
DWORD PacketFilter::BindUnbindInterface( bool bBind )
{
    DWORD dwFwAPiRetCode = ERROR_BAD_COMMAND;
    try
    {
        if( bBind )
        {
            RPC_STATUS rpcStatus = {0};
            FWPM_SUBLAYER0 SubLayer = {0};

            // Create a GUID for our packet filter layer.
            rpcStatus = ::UuidCreate( &SubLayer.subLayerKey );
            if( NO_ERROR == rpcStatus )
            {
                // Save GUID.
                ::CopyMemory( &m_subLayerGUID,
                              &SubLayer.subLayerKey,
                              sizeof( SubLayer.subLayerKey ) );

                // Populate packet filter layer information.
                SubLayer.displayData.name = FIREWALL_SUBLAYER_NAMEW;
                SubLayer.displayData.description = FIREWALL_SUBLAYER_NAMEW;
                SubLayer.flags = 0;
                SubLayer.weight = 0x100;

                // Add packet filter to our interface.
                dwFwAPiRetCode = ::FwpmSubLayerAdd0( m_hEngineHandle,
                                                     &SubLayer,
                                                     NULL );
            }
        }
        else
        {
            // Delete packet filter layer from our interface.
            dwFwAPiRetCode = ::FwpmSubLayerDeleteByKey0( m_hEngineHandle,
                                                         &m_subLayerGUID );
            ::ZeroMemory( &m_subLayerGUID, sizeof( GUID ) );
        }
    }
    catch(...)
    {
    }
    return dwFwAPiRetCode;
}

/******************************************************************************
PacketFilter::AddRemoveFilter - This method adds or removes a filter to an
                                existing interface.
*******************************************************************************/
DWORD PacketFilter::AddRemoveFilter( bool bAdd )
{
    DWORD dwFwAPiRetCode = ERROR_BAD_COMMAND;
	UINT64 filterid;
    try
    {
        if( bAdd )
        {
                        FWPM_FILTER0 Filter = {0};
                        FWPM_FILTER_CONDITION0 Condition = {0};

                        // Prepare filter.
                        Filter.subLayerKey = m_subLayerGUID;
                        Filter.displayData.name = FIREWALL_SERVICE_NAMEW;
                        Filter.weight.type = FWP_EMPTY;
                        Filter.filterCondition = &Condition;
                        Filter.numFilterConditions = 1;

						// First filter. Block IPv4 DNS.
						Filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
						Filter.action.type = FWP_ACTION_BLOCK;

                        // First condition
                        Condition.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
                        Condition.matchType = FWP_MATCH_EQUAL;
                        Condition.conditionValue.type = FWP_UINT16;
                        Condition.conditionValue.uint16 = 53;

                        // Add filter condition to our interface. Save filter id in filterids.
                        dwFwAPiRetCode = ::FwpmFilterAdd0( m_hEngineHandle,
                                                           &Filter,
                                                           NULL,
                                                           &filterid);
						printf("Filter (Block IPv4 DNS) added with ID=%I64d\r\n", filterid);
						filterids.push_back(filterid);

						// Second filter. Block IPv6 DNS.
						Filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;

						// Add filter condition to our interface. Save filter id in filterids.
						dwFwAPiRetCode = ::FwpmFilterAdd0(m_hEngineHandle,
							&Filter,
							NULL,
							&filterid);
						printf("Filter (Block IPv6 DNS) added with ID=%I64d\r\n", filterid);
						filterids.push_back(filterid);

						// Third filter. Permit all IPv4 traffic from TAP.
						Filter.action.type = FWP_ACTION_PERMIT;

						Condition.fieldKey = FWPM_CONDITION_IP_LOCAL_INTERFACE;
						Condition.matchType = FWP_MATCH_EQUAL;
						Condition.conditionValue.type = FWP_UINT64;

						for (std::vector<uint64_t>::iterator tapluid = tapluids.begin();
						tapluid != tapluids.end(); ++tapluid) {
							uint64_t tapluid64 = *tapluid;
							Filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
							Condition.conditionValue.uint64 = &tapluid64;

							// Add filter condition to our interface. Save filter id in filterids.
							dwFwAPiRetCode = ::FwpmFilterAdd0(m_hEngineHandle,
								&Filter,
								NULL,
								&filterid);
							printf("Filter (Permit all IPv4 traffic from TAP) added with ID=%I64d\r\n", filterid);
							filterids.push_back(filterid);

							// Forth filter. Permit all IPv6 traffic from TAP.
							Filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;

							// Add filter condition to our interface. Save filter id in filterids.
							dwFwAPiRetCode = ::FwpmFilterAdd0(m_hEngineHandle,
								&Filter,
								NULL,
								&filterid);
							printf("Filter (Permit all IPv6 traffic from TAP) added with ID=%I64d\r\n", filterid);
							filterids.push_back(filterid);
						}
        }
        else
        {
			for (int i = 0; i < filterids.size(); i++) {
				dwFwAPiRetCode = ::FwpmFilterDeleteById0(m_hEngineHandle,
					filterids[i]);
			}
			filterids.clear();
        }
    }
    catch(...)
    {
    }
    return dwFwAPiRetCode;
}


/******************************************************************************
PacketFilter::StartFirewall - This public method starts firewall.
*******************************************************************************/
BOOL PacketFilter::StartFirewall()
{
    BOOL bStarted = FALSE;

	NET_LUID tapluid;
	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;
	DWORD dwRetVal = 0;

	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	pAdapterInfo = (IP_ADAPTER_INFO *)MALLOC(sizeof(IP_ADAPTER_INFO));
	if (pAdapterInfo == NULL) {
		printf("Error allocating memory needed to call GetAdaptersinfo\n");
		return 1;
	}
	// Make an initial call to GetAdaptersInfo to get
	// the necessary size into the ulOutBufLen variable
	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		FREE(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO *)MALLOC(ulOutBufLen);
		if (pAdapterInfo == NULL) {
			printf("Error allocating memory needed to call GetAdaptersinfo\n");
			return 2;
		}
	}

	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
		pAdapter = pAdapterInfo;
		while (pAdapter) {
			if (strstr(pAdapter->Description, "TAP-Windows Adapter V9") != NULL) {
				if (ConvertInterfaceIndexToLuid(pAdapter->Index, &tapluid) == NO_ERROR)
					tapluids.push_back(tapluid.Value);
			}
			pAdapter = pAdapter->Next;
		}
	}
	else {
		printf("GetAdaptersInfo failed with error: %d\n", dwRetVal);
	}
	if (pAdapterInfo)
		FREE(pAdapterInfo);

	if (tapluids.size() <= 0) {
		printf("No TAP adapters found!\n");
		return 3;
	}

	printf("Found %zd TAP adapters\n", tapluids.size());

    try
    {
        // Create packet filter interface.
        if( ERROR_SUCCESS == CreateDeleteInterface( true ) )
        {
            // Bind to packet filter interface.
            if( ERROR_SUCCESS == BindUnbindInterface( true ) )
            {
                // Add filters.
                AddRemoveFilter( true );

                bStarted = TRUE;
            }
        }
    }
    catch(...)
    {
    }
    return bStarted;
}

/******************************************************************************
PacketFilter::StopFirewall - This method stops firewall.
*******************************************************************************/
BOOL PacketFilter::StopFirewall()
{
    BOOL bStopped = FALSE;
    try
    {
        // Remove all filters.
        AddRemoveFilter( false );

        // Unbind from packet filter interface.
        if( ERROR_SUCCESS == BindUnbindInterface( false ) )
        {
            // Delete packet filter interface.
            if( ERROR_SUCCESS == CreateDeleteInterface( false ) )
            {
                bStopped = TRUE;
            }
        }
    }
    catch(...)
    {
    }
    return bStopped;
}

void PrintTime()
{
	time_t rawtime;
	struct tm timeinfo;
	char str[26];
	time(&rawtime);
	localtime_s(&timeinfo, &rawtime);
	asctime_s(str, sizeof str, &timeinfo);
	str[24] = '\0';
	printf("%s ", str);
}

#ifdef SAMPLE_APP
/******************************************************************************
main - Entry point.
*******************************************************************************/
int main()
{
    try
    {
        PacketFilter pktFilter;

        // Start firewall.
		
        if( pktFilter.StartFirewall() )
        {
            printf( "\nFirewall started successfully...\n" );
        }
        else
        {
            printf( "\nError starting firewall. GetLastError() 0x%x", ::GetLastError() );
        }

        // Wait.
        printf( "\nPress any key to stop firewall...\n" );
        _getch();

        // Stop firewall.
        if( pktFilter.StopFirewall() )
        {
            printf( "\nFirewall stopped successfully...\n" );
        }
        else
        {
            printf( "\nError stopping firewall. GetLastError() 0x%x", ::GetLastError() );
        }

        // Quit.
        printf( "\nPress any key to exit...\n" );
        _getch();
    }
    catch(...)
    {
    }
}
#endif //SAMPLE_APP

#ifndef SAMPLE_APP
struct plugin_context {
	PacketFilter pktFilter;
};

OPENVPN_EXPORT openvpn_plugin_handle_t
openvpn_plugin_open_v1(unsigned int *type_mask, const char *argv[], const char *envp[])
{
	struct plugin_context *context;

	/*
	* Allocate our context
	*/
	context = (struct plugin_context *) calloc(1, sizeof(struct plugin_context));

	/*
	* We are only interested in intercepting the
	* --auth-user-pass-verify callback.
	*/
	*type_mask = OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_UP) | OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_DOWN);

	return (openvpn_plugin_handle_t)context;
}

OPENVPN_EXPORT void
openvpn_plugin_close_v1(openvpn_plugin_handle_t handle)
{
	struct plugin_context *context = (struct plugin_context *) handle;
	free(context);
}

OPENVPN_EXPORT int
openvpn_plugin_func_v1(openvpn_plugin_handle_t handle, const int type, const char *argv[], const char *envp[])
{
	struct plugin_context *context = (struct plugin_context *) handle;

	if (type == OPENVPN_PLUGIN_UP) {
		PrintTime();
		printf("PLUGIN: Starting firewall\n");
		if (context->pktFilter.StartFirewall())
			return OPENVPN_PLUGIN_FUNC_SUCCESS;
		else {
			PrintTime();
			printf("PLUGIN: Start failed!\n");
			return OPENVPN_PLUGIN_FUNC_ERROR;
		}
	}
	if (type == OPENVPN_PLUGIN_DOWN) {
		PrintTime();
		printf("PLUGIN: Stopping firewall\n");
		if (context->pktFilter.StopFirewall())
				return OPENVPN_PLUGIN_FUNC_SUCCESS;
		else {
			PrintTime();
			printf("PLUGIN: Can't stop firewall!\n");
			return OPENVPN_PLUGIN_FUNC_ERROR;
		}

	}
		PrintTime();
		printf("PLUGIN: Unknown handler!\n");
		return OPENVPN_PLUGIN_FUNC_SUCCESS;
}
#endif //SAMPLE_APP
