import React, { useState, useEffect } from 'react';
import {
  Modal,
  Box,
  Typography,
  TextField,
  Button,
  IconButton,
  MenuItem,
  Alert,
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

const EditReceiptModal = ({ open, onClose, receipt, onSave, onReceiptUpdated }) => {
  const [formData, setFormData] = useState({
    store_name: '',
    phone: '',
    website: '',
    address: '',
    date: '',
    time: '',
    total_payment: '',
    payment_method: '',
    expense_category: '',
    line_items: [],
  });
  const [error, setError] = useState('');

  useEffect(() => {
    if (receipt) {
      setFormData({
        ...receipt,
        line_items: receipt.line_items || [],
      });
    }
  }, [receipt]);

  const handleChange = (field) => (event) => {
    setFormData({
      ...formData,
      [field]: event.target.value,
    });
  };

  const handleLineItemChange = (index, value) => {
    const newLineItems = [...formData.line_items];
    newLineItems[index] = value;
    setFormData({
      ...formData,
      line_items: newLineItems,
    });
  };

  const handleAddLineItem = () => {
    setFormData({
      ...formData,
      line_items: [...formData.line_items, ''],
    });
  };

  const handleRemoveLineItem = (index) => {
    setFormData({
      ...formData,
      line_items: formData.line_items.filter((_, i) => i !== index),
    });
  };

  const handleSubmit = async () => {
    try {
      const response = await axios.post('/update_receipt', {
        ...formData,
        username: receipt.username,
        processed_at: receipt.processed_at,
        line_items: formData.line_items.filter(item => item.trim() !== ''),
      });
      
      if (response.data && response.data.message === "Receipt updated successfully") {
        setError('');
        const updatedReceipt = {
          ...formData,
          username: receipt.username,
          processed_at: receipt.processed_at,
          status: receipt.status,
          id: receipt.id,
          image_filename: receipt.image_filename
        };
        if (onSave) {
          onSave(updatedReceipt);
        } else if (onReceiptUpdated) {
          onReceiptUpdated(updatedReceipt);
        }
        onClose();
      } else {
        setError('Failed to update receipt: Unexpected response');
      }
    } catch (error) {
      setError(error.response?.data?.error || 'Failed to update receipt');
    }
  };

  if (!receipt) return null;

  return (
    <Modal open={open} onClose={onClose}>
      <Box sx={modalStyle}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
          <Typography variant="h5" component="h2">
            Edit Receipt
          </Typography>
          <IconButton onClick={onClose}>
            <CloseIcon />
          </IconButton>
        </Box>

        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 3 }}>
          <Box>
            <Typography variant="subtitle1" color="primary" sx={{ mb: 2 }}>
              Store Information
            </Typography>
            <TextField
              fullWidth
              label="Store Name"
              value={formData.store_name}
              onChange={handleChange('store_name')}
              margin="normal"
            />
            <TextField
              fullWidth
              label="Phone"
              value={formData.phone}
              onChange={handleChange('phone')}
              margin="normal"
            />
            <TextField
              fullWidth
              label="Website"
              value={formData.website}
              onChange={handleChange('website')}
              margin="normal"
            />
            <TextField
              fullWidth
              label="Address"
              value={formData.address}
              onChange={handleChange('address')}
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
              value={formData.date}
              onChange={handleChange('date')}
              margin="normal"
              InputLabelProps={{ shrink: true }}
            />
            <TextField
              fullWidth
              label="Time"
              type="time"
              value={formData.time}
              onChange={handleChange('time')}
              margin="normal"
              InputLabelProps={{ shrink: true }}
            />
            <TextField
              fullWidth
              label="Total Payment"
              type="number"
              value={formData.total_payment ? parseFloat(formData.total_payment.toString().replace(/[$,]/g, '')) : ''}
              onChange={(e) => {
                const value = e.target.value;
                setFormData({
                  ...formData,
                  total_payment: value || value === 0 ? value.toString() : ''
                });
              }}
              margin="normal"
              InputProps={{
                startAdornment: '$',
                step: "0.01"
              }}
            />
            <TextField
              fullWidth
              label="Payment Method"
              value={formData.payment_method}
              onChange={handleChange('payment_method')}
              margin="normal"
            />
            <TextField
              select
              fullWidth
              label="Expense Category"
              value={formData.expense_category}
              onChange={handleChange('expense_category')}
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
            {formData.line_items.map((item, index) => (
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
          <Button variant="outlined" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="contained" onClick={handleSubmit}>
            Save Changes
          </Button>
        </Box>
      </Box>
    </Modal>
  );
};

export default EditReceiptModal; 