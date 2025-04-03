import React, { useState } from 'react';
import {
  Modal,
  Box,
  Typography,
  Button,
  TextField,
  MenuItem,
  CircularProgress,
  Alert,
  IconButton,
  List,
  ListItem,
} from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';
import axios from 'axios';

const modalStyle = {
  position: 'absolute',
  top: '50%',
  left: '50%',
  transform: 'translate(-50%, -50%)',
  width: '90%',
  maxWidth: '800px',
  bgcolor: 'background.paper',
  boxShadow: 24,
  p: 4,
  borderRadius: 2,
  maxHeight: '90vh',
  overflow: 'auto',
};

const expenseCategories = [
  'travel',
  'meals',
  'office supplies',
  'entertainment',
  'training',
  'transportation'
];

const UploadModal = ({ open, onClose, onReceiptSaved }) => {
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [receiptData, setReceiptData] = useState(null);
  const [lineItems, setLineItems] = useState([]);

  const handleFileChange = (event) => {
    const selectedFile = event.target.files[0];
    if (selectedFile) {
      setFile(selectedFile);
      setError('');
    }
  };

  const handleProcessReceipt = async () => {
    if (!file) return;

    setLoading(true);
    setError('');

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await axios.post('/process_receipt', formData);
      setReceiptData(response.data);
      setLineItems(response.data.line_items || []);
    } catch (error) {
      setError(error.response?.data?.error || 'Failed to process receipt');
    } finally {
      setLoading(false);
    }
  };

  const handleAddLineItem = () => {
    setLineItems([...lineItems, '']);
  };

  const handleLineItemChange = (index, value) => {
    const newItems = [...lineItems];
    newItems[index] = value;
    setLineItems(newItems);
  };

  const handleRemoveLineItem = (index) => {
    setLineItems(lineItems.filter((_, i) => i !== index));
  };

  const handleSave = async () => {
    try {
      const data = {
        ...receiptData,
        line_items: lineItems.filter(item => item.trim() !== ''),
      };

      await axios.post('/save_receipt', data);
      onReceiptSaved();
      handleClose();
    } catch (error) {
      setError(error.response?.data?.error || 'Failed to save receipt');
    }
  };

  const handleClose = () => {
    setFile(null);
    setReceiptData(null);
    setLineItems([]);
    setError('');
    onClose();
  };

  return (
    <Modal open={open} onClose={handleClose}>
      <Box sx={modalStyle}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
          <Typography variant="h5" component="h2">
            Upload Receipt
          </Typography>
          <IconButton onClick={handleClose}>
            <CloseIcon />
          </IconButton>
        </Box>

        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        {!receiptData && (
          <Box sx={{ mb: 3 }}>
            <input
              accept="image/*,.pdf"
              style={{ display: 'none' }}
              id="receipt-file"
              type="file"
              onChange={handleFileChange}
            />
            <label htmlFor="receipt-file">
              <Button variant="contained" component="span">
                Choose File
              </Button>
            </label>
            {file && (
              <>
                <Typography variant="body2" sx={{ mt: 1, mb: 2 }}>
                  Selected: {file.name}
                </Typography>
                <Button
                  variant="contained"
                  onClick={handleProcessReceipt}
                  disabled={loading}
                >
                  Process Receipt
                </Button>
              </>
            )}
          </Box>
        )}

        {loading && (
          <Box sx={{ display: 'flex', justifyContent: 'center', mb: 2 }}>
            <CircularProgress />
          </Box>
        )}

        {receiptData && (
          <>
            <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 3 }}>
              <Box>
                <Typography variant="subtitle1" color="primary" sx={{ mb: 2 }}>
                  Store Information
                </Typography>
                <TextField
                  fullWidth
                  label="Store Name"
                  value={receiptData.store_name || ''}
                  onChange={(e) => setReceiptData({ ...receiptData, store_name: e.target.value })}
                  margin="normal"
                />
                <TextField
                  fullWidth
                  label="Phone"
                  value={receiptData.phone || ''}
                  onChange={(e) => setReceiptData({ ...receiptData, phone: e.target.value })}
                  margin="normal"
                />
                <TextField
                  fullWidth
                  label="Website"
                  value={receiptData.website || ''}
                  onChange={(e) => setReceiptData({ ...receiptData, website: e.target.value })}
                  margin="normal"
                />
                <TextField
                  fullWidth
                  label="Address"
                  value={receiptData.address || ''}
                  onChange={(e) => setReceiptData({ ...receiptData, address: e.target.value })}
                  margin="normal"
                  multiline
                  rows={2}
                />
              </Box>

              <Box>
                <Typography variant="subtitle1" color="primary" sx={{ mb: 2 }}>
                  Transaction Details
                </Typography>
                <TextField
                  fullWidth
                  label="Date"
                  type="date"
                  value={receiptData.date || ''}
                  onChange={(e) => setReceiptData({ ...receiptData, date: e.target.value })}
                  margin="normal"
                  InputLabelProps={{ shrink: true }}
                />
                <TextField
                  fullWidth
                  label="Time"
                  type="time"
                  value={receiptData.time || ''}
                  onChange={(e) => setReceiptData({ ...receiptData, time: e.target.value })}
                  margin="normal"
                  InputLabelProps={{ shrink: true }}
                />
                <TextField
                  fullWidth
                  label="Total Payment"
                  type="number"
                  value={receiptData.total_payment?.replace('$', '') || ''}
                  onChange={(e) => setReceiptData({ ...receiptData, total_payment: e.target.value })}
                  margin="normal"
                  InputProps={{
                    startAdornment: '$',
                  }}
                />
                <TextField
                  fullWidth
                  label="Payment Method"
                  value={receiptData.payment_method || ''}
                  onChange={(e) => setReceiptData({ ...receiptData, payment_method: e.target.value })}
                  margin="normal"
                />
                <TextField
                  select
                  fullWidth
                  label="Expense Category"
                  value={receiptData.expense_category || ''}
                  onChange={(e) => setReceiptData({ ...receiptData, expense_category: e.target.value })}
                  margin="normal"
                >
                  {expenseCategories.map((category) => (
                    <MenuItem key={category} value={category}>
                      {category}
                    </MenuItem>
                  ))}
                </TextField>
              </Box>
            </Box>

            <Box sx={{ mt: 4 }}>
              <Typography variant="subtitle1" color="primary" sx={{ mb: 2 }}>
                Line Items
              </Typography>
              <List>
                {lineItems.map((item, index) => (
                  <ListItem key={index} sx={{ px: 0 }}>
                    <TextField
                      fullWidth
                      size="small"
                      value={item}
                      onChange={(e) => handleLineItemChange(index, e.target.value)}
                      sx={{ mr: 2 }}
                    />
                    <Button
                      variant="outlined"
                      color="error"
                      onClick={() => handleRemoveLineItem(index)}
                    >
                      Remove
                    </Button>
                  </ListItem>
                ))}
              </List>
              <Button
                variant="outlined"
                onClick={handleAddLineItem}
                sx={{ mt: 2 }}
              >
                Add Item
              </Button>
            </Box>

            <Box sx={{ mt: 4, display: 'flex', justifyContent: 'flex-end', gap: 2 }}>
              <Button variant="outlined" onClick={handleClose}>
                Cancel
              </Button>
              <Button variant="contained" onClick={handleSave}>
                Save Receipt
              </Button>
            </Box>
          </>
        )}
      </Box>
    </Modal>
  );
};

export default UploadModal; 