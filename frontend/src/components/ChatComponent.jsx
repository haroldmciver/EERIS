import React, { useState, useRef, useEffect } from 'react';
import {
  Box,
  TextField,
  Button,
  Typography,
  Paper,
  List,
  ListItem,
  CircularProgress,
  IconButton,
  Tooltip
} from '@mui/material';
import SendIcon from '@mui/icons-material/Send';
import DeleteIcon from '@mui/icons-material/Delete';
import axios from 'axios';

const ChatComponent = () => {
  const [message, setMessage] = useState('');
  const username = sessionStorage.getItem('username');
  const chatHistoryKey = `chatHistory_${username}`;
  
  const [chatHistory, setChatHistory] = useState(() => {
    // Load chat history from session storage, specific to this user
    const savedHistory = sessionStorage.getItem(chatHistoryKey);
    return savedHistory ? JSON.parse(savedHistory) : [];
  });
  
  const [isLoading, setIsLoading] = useState(false);
  const chatEndRef = useRef(null);

  // Clear chat history if stored for a different user
  useEffect(() => {
    // Check if there's any stored chat history
    const keys = Object.keys(sessionStorage);
    for (const key of keys) {
      // If it starts with chatHistory_ but is not for the current user, remove it
      if (key.startsWith('chatHistory_') && key !== chatHistoryKey) {
        sessionStorage.removeItem(key);
      }
    }
  }, [chatHistoryKey]);

  // Scroll to bottom of chat when history changes
  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    // Save chat history to session storage, specific to this user
    sessionStorage.setItem(chatHistoryKey, JSON.stringify(chatHistory));
  }, [chatHistory, chatHistoryKey]);

  const handleSendMessage = async () => {
    if (!message.trim()) return;

    // Add user message to chat
    const userMessage = { sender: 'user', text: message, timestamp: new Date().toISOString() };
    const updatedHistory = [...chatHistory, userMessage];
    setChatHistory(updatedHistory);
    setIsLoading(true);
    
    const userQuery = message;
    setMessage('');

    try {
      // Prepare conversation history for the backend
      // We'll send the last 10 messages (or fewer if not available) to keep context manageable
      const conversationContext = updatedHistory
        .slice(-10)  // Get last 10 messages
        .map(msg => ({
          role: msg.sender === 'user' ? 'user' : 'assistant',
          content: msg.text
        }));
      
      // Send message and conversation history to backend
      const response = await axios.post('/chat', { 
        message: userQuery,
        conversation_history: conversationContext
      });
      
      // Add assistant response to chat
      const assistantMessage = { 
        sender: 'assistant', 
        text: response.data.response,
        timestamp: new Date().toISOString()
      };
      setChatHistory(prev => [...prev, assistantMessage]);
    } catch (error) {
      console.error('Error sending message:', error);
      const errorMessage = { 
        sender: 'assistant', 
        text: 'Sorry, I encountered an error processing your request. Please try again.',
        timestamp: new Date().toISOString(),
        isError: true
      };
      setChatHistory(prev => [...prev, errorMessage]);
    }

    setIsLoading(false);
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };
  
  const clearChatHistory = () => {
    setChatHistory([]);
    sessionStorage.removeItem(chatHistoryKey);
  };

  return (
    <Box sx={{ 
      display: 'flex', 
      flexDirection: 'column', 
      height: '100%',
      flex: 1
    }}>
      <Box sx={{ 
        display: 'flex', 
        justifyContent: 'space-between',
        alignItems: 'center',
        mb: 2
      }}>
        <Typography variant="h6">
          Receipt Data Assistant
        </Typography>
        <Tooltip title="Clear chat history">
          <IconButton 
            size="small" 
            onClick={clearChatHistory}
            disabled={chatHistory.length === 0}
          >
            <DeleteIcon fontSize="small" />
          </IconButton>
        </Tooltip>
      </Box>
      
      <Paper 
        elevation={0} 
        sx={{ 
          flexGrow: 1, 
          display: 'flex',
          flexDirection: 'column',
          bgcolor: '#f5f5f5',
          mb: 2,
          p: 2,
          borderRadius: 1,
          overflow: 'hidden'
        }}
      >
        <List sx={{ 
          flexGrow: 1, 
          overflow: 'auto',
          width: '100%',
          pb: 2
        }}>
          {chatHistory.length === 0 ? (
            <ListItem>
              <Typography color="text.secondary" align="center" sx={{ width: '100%' }}>
                Ask me questions about your receipts! For example:
                <br />
                "What was my highest expense this month?"
                <br />
                "How much did I spend at restaurants?"
                <br />
                "Show me all my receipts from Amazon"
              </Typography>
            </ListItem>
          ) : (
            chatHistory.map((chat, index) => (
              <ListItem
                key={index}
                sx={{
                  justifyContent: chat.sender === 'user' ? 'flex-end' : 'flex-start',
                  mb: 1
                }}
              >
                <Paper
                  elevation={1}
                  sx={{
                    p: 1.5,
                    maxWidth: '85%',
                    bgcolor: chat.sender === 'user' ? '#e3f2fd' : chat.isError ? '#ffebee' : 'white',
                    borderRadius: 2
                  }}
                >
                  <Typography variant="body1" sx={{ whiteSpace: 'pre-wrap' }}>
                    {chat.text}
                  </Typography>
                  <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 0.5, textAlign: 'right' }}>
                    {new Date(chat.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </Typography>
                </Paper>
              </ListItem>
            ))
          )}
          {isLoading && (
            <ListItem sx={{ justifyContent: 'flex-start', mb: 1 }}>
              <Paper
                elevation={1}
                sx={{
                  p: 1.5,
                  bgcolor: 'white',
                  borderRadius: 2,
                  display: 'flex',
                  alignItems: 'center'
                }}
              >
                <CircularProgress size={20} sx={{ mr: 1 }} />
                <Typography variant="body2">Thinking...</Typography>
              </Paper>
            </ListItem>
          )}
          <div ref={chatEndRef} />
        </List>
      </Paper>
      
      <Box sx={{ display: 'flex', alignItems: 'center' }}>
        <TextField
          fullWidth
          variant="outlined"
          placeholder="Ask about your receipts..."
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          onKeyPress={handleKeyPress}
          size="small"
          sx={{ mr: 1 }}
          disabled={isLoading}
        />
        <Button 
          variant="contained" 
          color="primary"
          endIcon={<SendIcon />}
          onClick={handleSendMessage}
          disabled={isLoading || !message.trim()}
        >
          Send
        </Button>
      </Box>
    </Box>
  );
};

export default ChatComponent; 