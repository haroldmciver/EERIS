import React from 'react';
import {
  Modal,
  Box,
  Typography,
  IconButton,
  List,
  ListItem,
  ListItemText,
  Divider,
  Button,
} from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';
import EditIcon from '@mui/icons-material/Edit';

const modalStyle = {
  position: 'absolute',
  top: '50%',
  left: '50%',
  transform: 'translate(-50%, -50%)',
  width: '95%',
  maxWidth: '1200px',
  bgcolor: 'background.paper',
  boxShadow: 24,
  p: 4,
  borderRadius: 2,
  maxHeight: '90vh',
  overflow: 'auto',
  display: 'flex',
  gap: 3,
};

const ViewReceiptModal = ({ open, onClose, receipt, onEdit, userRole, onStatusChange }) => {
  if (!receipt) return null;

  const formatDate = (date) => {
    if (!date) return '';
    return new Date(date).toLocaleDateString();
  };

  const formatTime = (time) => {
    if (!time) return '';
    return new Date(`1970-01-01T${time}`).toLocaleTimeString();
  };

  const formatCurrency = (amount) => {
    if (!amount) return '$0.00';
    // Remove any existing currency symbol and commas
    const cleanAmount = amount.toString().replace(/[$,]/g, '');
    const numericAmount = parseFloat(cleanAmount);
    if (isNaN(numericAmount)) return '$0.00';
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD'
    }).format(numericAmount);
  };

  return (
    <Modal open={open} onClose={onClose}>
      <Box sx={modalStyle}>
        {/* Left side - Receipt Details */}
        <Box sx={{ flex: 1, overflow: 'auto' }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
            <Typography variant="h5" component="h2">
              Receipt Details
            </Typography>
            <Box>
              {userRole === 'employee' && (
                <IconButton onClick={onEdit} sx={{ mr: 1 }}>
                  <EditIcon />
                </IconButton>
              )}
              <IconButton onClick={onClose}>
                <CloseIcon />
              </IconButton>
            </Box>
          </Box>

          <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 3, mb: 4 }}>
            <Box>
              <Typography variant="subtitle1" color="primary">Store Information</Typography>
              <List dense>
                <ListItem>
                  <ListItemText primary="Store Name" secondary={receipt.store_name} />
                </ListItem>
                <ListItem>
                  <ListItemText primary="Phone" secondary={receipt.phone} />
                </ListItem>
                <ListItem>
                  <ListItemText primary="Website" secondary={receipt.website} />
                </ListItem>
                <ListItem>
                  <ListItemText primary="Address" secondary={receipt.address} />
                </ListItem>
              </List>
            </Box>

            <Box>
              <Typography variant="subtitle1" color="primary">Transaction Details</Typography>
              <List dense>
                <ListItem>
                  <ListItemText 
                    primary="Date" 
                    secondary={formatDate(receipt.date)}
                  />
                </ListItem>
                <ListItem>
                  <ListItemText 
                    primary="Time" 
                    secondary={formatTime(receipt.time)}
                  />
                </ListItem>
                <ListItem>
                  <ListItemText 
                    primary="Total Payment" 
                    secondary={formatCurrency(receipt.total_payment)}
                  />
                </ListItem>
                <ListItem>
                  <ListItemText 
                    primary="Payment Method" 
                    secondary={receipt.payment_method}
                  />
                </ListItem>
                <ListItem>
                  <ListItemText 
                    primary="Expense Category" 
                    secondary={receipt.expense_category}
                  />
                </ListItem>
                <ListItem>
                  <ListItemText 
                    primary="Status" 
                    secondary={receipt.status}
                  />
                </ListItem>
              </List>
            </Box>
          </Box>

          <Divider sx={{ mb: 3 }} />

          <Typography variant="subtitle1" color="primary" sx={{ mb: 2 }}>
            Line Items
          </Typography>
          <List dense>
            {receipt.line_items?.map((item, index) => (
              <ListItem key={index}>
                <ListItemText primary={item} />
              </ListItem>
            ))}
          </List>

          {userRole === 'supervisor' && receipt.status === 'submitted' && (
            <Box sx={{ mt: 3, display: 'flex', gap: 2, justifyContent: 'flex-end' }}>
              <Button
                variant="contained"
                color="success"
                onClick={() => onStatusChange(receipt.username, receipt.processed_at, 'approved')}
              >
                Approve
              </Button>
              <Button
                variant="contained"
                color="error"
                onClick={() => onStatusChange(receipt.username, receipt.processed_at, 'denied')}
              >
                Reject
              </Button>
            </Box>
          )}
        </Box>

        {/* Right side - Receipt Image */}
        <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
          {receipt.image_filename && (
            <>
              {receipt.image_filename.toLowerCase().endsWith('.pdf') ? (
                <object
                  data={`http://localhost:5000/uploads/${receipt.image_filename}`}
                  type="application/pdf"
                  style={{
                    width: '100%',
                    height: '80vh',
                  }}
                >
                  <Box sx={{ textAlign: 'center', p: 2 }}>
                    <Typography color="error">
                      Unable to display PDF. 
                      <a href={`http://localhost:5000/uploads/${receipt.image_filename}`} target="_blank" rel="noopener noreferrer">
                        Click here to open in new tab
                      </a>
                    </Typography>
                  </Box>
                </object>
              ) : (
                <Box
                  component="img"
                  src={`http://localhost:5000/uploads/${receipt.image_filename}`}
                  alt="Receipt"
                  sx={{
                    maxWidth: '100%',
                    maxHeight: '80vh',
                    objectFit: 'contain',
                    border: '1px solid #ddd',
                    borderRadius: 1,
                    boxShadow: 1,
                  }}
                />
              )}
            </>
          )}
        </Box>
      </Box>
    </Modal>
  );
};

export default ViewReceiptModal; 