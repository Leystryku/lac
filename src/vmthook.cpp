#include "vmthook.h"

void* hooked[0xFFFF];
int hookcount;

bool first = true;

VMTHook::VMTHook(void* instance)
{
	if (first)
	{
		first = false;
		memset(hooked, 0, 0xFFFF);
	}
	
	if( !instance)
		return;
	/*
	
	for (int i = 0; i < hookcount + 1; i++)
	{
		if (!hooked[i] && !hooked[i + 1] && !hooked[i + 2] && !hooked[i + 3])
			break;

		if (hooked[i] && hooked[i] == *(void***)instance)
			return;



	}
	*/

	m_pInstance = (void***) instance;

	if ( !m_pInstance )
		return;

	m_pOriginalVTable = *m_pInstance;

	if ( !m_pOriginalVTable )
		return;

	hooked[hookcount++] = instance;

	//Count number of Pointers in the table


	m_iNumIndices = 0;

	while (m_pOriginalVTable[m_iNumIndices])
	{
		m_iNumIndices++;
	}

	if (!m_iNumIndices)
		return;

	//Allocate memory on the heap for our own copy of the table
	int size = sizeof(int) * (m_iNumIndices + 4);

	m_pNewVTable = (void**)malloc(size);
	
	if ( !m_pNewVTable )
		return;


	int i = -2;

	while (++i < m_iNumIndices)
	{
		m_pNewVTable[i] = m_pOriginalVTable[i];

	}


	*m_pInstance = m_pNewVTable;
	hooked[hookcount++] = m_pNewVTable;

}

VMTHook::~VMTHook()
{

	//Rewrite old pointer

	if (!m_pInstance)
		return;
	
	if (!*m_pInstance)
		return;

	if (!m_pOriginalVTable)
		return;	

	if (m_pNewVTable)
	{
		for (int i = 0; i < m_iNumIndices; i++)
		{
			if (m_pNewVTable[i] != m_pOriginalVTable[i])
			{
				m_pNewVTable[i] = m_pOriginalVTable[i];
			}
		}
		//free(m_pNewVTable);
	}
		

	*m_pInstance = m_pOriginalVTable;

	return;

}

int VMTHook::tellCount( )
{

	return m_iNumIndices;
}

void* VMTHook::hookFunction(int iIndex, void* pfnHook)
{

	//Valid index?
	if(iIndex >= m_iNumIndices)
		return NULL;

	if ( !m_pOriginalVTable[iIndex] )
		return NULL;

	if (pfnHook == m_pOriginalVTable[iIndex])
		return 0;

	//Write new pointer
	m_pNewVTable[iIndex] = pfnHook;
 
	//And return pointer to original function
	return m_pOriginalVTable[iIndex];
}

void* VMTHook::unhookFunction(int iIndex)
{

	//Valid index?
	if(iIndex >= m_iNumIndices)
		return NULL;

	if ( !m_pOriginalVTable[iIndex] )
		return NULL;

	//Rewrite old pointer
	m_pNewVTable[iIndex] = m_pOriginalVTable[iIndex];
	
	//And return pointer to original function
	return m_pOriginalVTable[iIndex];
}

void* VMTHook::GetMethod(int iIndex)
{
	return m_pOriginalVTable[iIndex];
}
void* VMTHook::GetHookedMethod(int iIndex)
{
	return m_pNewVTable[iIndex];
}