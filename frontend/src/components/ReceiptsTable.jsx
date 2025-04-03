import React from 'react';
import {
  Button,
  Box,
  ButtonGroup
} from '@mui/material';
import { DataGrid } from '@mui/x-data-grid';

const ReceiptsTable = ({ receipts, isSupervisor, onViewReceipt, onEditReceipt, onUpdateStatus }) => {
  const getStatusActions = (params) => {
    if (isSupervisor && params.row.status === 'submitted') {
      return (
        <ButtonGroup size="small">
          <Button
            onClick={() => onUpdateStatus(params.row.username, params.row.processed_at, 'approved')}
            color="primary"
            variant="contained"
            size="small"
          >
            Approve
          </Button>
          <Button
            onClick={() => onUpdateStatus(params.row.username, params.row.processed_at, 'denied')}
            color="error"
            variant="contained"
            size="small"
          >
            Deny
          </Button>
        </ButtonGroup>
      );
    }
    return params.value;
  };

  const columns = [
    {
      field: 'actions',
      headerName: 'Actions',
      flex: 0.8,
      headerAlign: 'center',
      align: 'center',
      sortable: false,
      resizable: false,
      renderCell: (params) => (
        <ButtonGroup size="small">
          <Button
            onClick={() => onViewReceipt(params.row)}
            color="primary"
            variant="contained"
            size="small"
          >
            View
          </Button>
          <Button
            onClick={() => onEditReceipt(params.row)}
            color="secondary"
            variant="contained"
            size="small"
          >
            Edit
          </Button>
        </ButtonGroup>
      ),
    },
    ...(isSupervisor ? [{
      field: 'username',
      headerName: 'User',
      flex: 0.8,
      headerAlign: 'center',
      align: 'center',
      sortable: true,
      resizable: false,
    }] : []),
    { 
      field: 'store_name', 
      headerName: 'Store', 
      flex: 2,
      headerAlign: 'left',
      align: 'left',
      sortable: true,
      resizable: false,
    },
    { 
      field: 'date', 
      headerName: 'Date', 
      flex: 0.8,
      headerAlign: 'center',
      align: 'center',
      sortable: true,
      resizable: false,
      renderCell: (params) => {
        if (!params.row.date) return '';
        const [year, month, day] = params.row.date.split('-');
        return `${month}/${day}/${year}`;
      }
    },
    { 
      field: 'total_payment', 
      headerName: 'Total', 
      flex: 0.8,
      headerAlign: 'right',
      align: 'right',
      sortable: true,
      resizable: false,
      valueFormatter: (params) => {
        const amount = params.value;
        if (!amount) return '$0.00';
        const numericValue = parseFloat(amount.replace(/[^0-9.-]+/g, ''));
        return `$${numericValue.toFixed(2)}`;
      },
      sortComparator: (v1, v2) => {
        const num1 = parseFloat(v1.replace(/[^0-9.-]+/g, '')) || 0;
        const num2 = parseFloat(v2.replace(/[^0-9.-]+/g, '')) || 0;
        return num1 - num2;
      },
      renderCell: (params) => {
        const amount = params.row.total_payment;
        if (!amount) return '$0.00';
        const numericValue = parseFloat(amount.replace(/[^0-9.-]+/g, ''));
        return `$${numericValue.toFixed(2)}`;
      }
    },
    { 
      field: 'expense_category', 
      headerName: 'Category', 
      flex: 1,
      headerAlign: 'center',
      align: 'center',
      sortable: true,
      resizable: false,
    },
    {
      field: 'status',
      headerName: 'Status',
      flex: 1.2,
      headerAlign: 'center',
      align: 'center',
      sortable: true,
      resizable: false,
      renderCell: (params) => getStatusActions(params),
    },
  ];

  return (
    <Box sx={{ 
      height: '100%', 
      width: '100%',
      '& .MuiDataGrid-root': {
        backgroundColor: 'white',
      },
    }}>
      <DataGrid
        rows={receipts.map((receipt, index) => ({
          ...receipt,
          id: receipt.processed_at || index,
        }))}
        columns={columns}
        pageSize={10}
        rowsPerPageOptions={[10, 25, 50, 100]}
        disableSelectionOnClick
        disableColumnMenu
        disableColumnFilter
        autoHeight
        sx={{
          '& .MuiDataGrid-cell': {
            fontSize: '0.875rem',
            padding: '8px',
            whiteSpace: 'normal',
            minHeight: '52px !important',
          },
          '& .MuiDataGrid-columnHeaders': {
            backgroundColor: '#f5f5f5',
            borderBottom: '2px solid #e0e0e0',
          },
          '& .MuiDataGrid-row': {
            minHeight: '52px !important',
          },
          '& .MuiDataGrid-row:hover': {
            backgroundColor: '#f8f8f8',
          },
          '& .MuiDataGrid-columnSeparator': {
            display: 'none',
          },
          '& .MuiDataGrid-cell--withRenderer': {
            padding: '4px',
          },
        }}
      />
    </Box>
  );
};

export default ReceiptsTable; 