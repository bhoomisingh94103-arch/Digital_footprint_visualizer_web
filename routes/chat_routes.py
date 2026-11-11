import uuid
from flask import Blueprint, request, jsonify, session
from flask_login import current_user
from models import db, ChatHistory
from services.ai_assistant_service import ask_privacy_guardian
from datetime import datetime, timezone

chat_bp = Blueprint('chat', __name__, url_prefix='/api/chat')

@chat_bp.route('/', methods=['POST'])
def send_chat():
    """
    Handle chatbot questions to Privacy Guardian.
    """
    data = request.get_json() or {}
    query = data.get('message', '').strip()
    
    if not query:
        return jsonify({'success': False, 'error': 'Query message is empty.'}), 400
        
    session_id = session.get('chat_session_id')
    if not session_id:
        session_id = str(uuid.uuid4())
        session['chat_session_id'] = session_id
        
    user_id = current_user.id if current_user.is_authenticated else None
    
    # Retrieve user assessment context if available
    user_context = session.get('last_assessment')
    
    # Query assistant service
    result = ask_privacy_guardian(query, user_context)
    
    # Save conversation log to database
    user_msg = ChatHistory(
        user_id=user_id,
        session_id=session_id,
        role='user',
        content=query,
        model_used=result.get('engine', 'Privacy Guardian Expert Engine'),
        timestamp=datetime.now(timezone.utc)
    )
    bot_msg = ChatHistory(
        user_id=user_id,
        session_id=session_id,
        role='assistant',
        content=result.get('response', ''),
        model_used=result.get('engine', 'Privacy Guardian Expert Engine'),
        timestamp=datetime.now(timezone.utc)
    )
    db.session.add(user_msg)
    db.session.add(bot_msg)
    db.session.commit()
    
    return jsonify({
        'success': True,
        'response': result.get('response'),
        'engine': result.get('engine'),
        'is_ai': result.get('is_ai', False),
        'error_notice': result.get('error_notice')
    })


@chat_bp.route('/history', methods=['GET'])
def get_chat_history():
    """Fetch recent chat messages for current session."""
    session_id = session.get('chat_session_id')
    if not session_id:
        return jsonify({'messages': []})
        
    logs = ChatHistory.query.filter_by(session_id=session_id).order_by(ChatHistory.timestamp.asc()).limit(30).all()
    messages = [{
        'role': l.role,
        'content': l.content,
        'engine': l.model_used,
        'timestamp': l.timestamp.strftime("%H:%M")
    } for l in logs]
    
    return jsonify({'messages': messages})


@chat_bp.route('/clear', methods=['POST'])
def clear_chat_history():
    """Clear chat session."""
    session_id = session.get('chat_session_id')
    if session_id:
        ChatHistory.query.filter_by(session_id=session_id).delete()
        db.session.commit()
        session.pop('chat_session_id', None)
    return jsonify({'success': True})

